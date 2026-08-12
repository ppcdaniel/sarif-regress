# Engineering case study: conservative SARIF regression matching

This case study separates measured facts from engineering interpretation. The figures come from
versioned project reports and the clean sparse-SARIF experiment; they are not estimates. The work
improved two producer families, corrected one classification defect, and preserved a deliberate
safe stop for evidence-poor PMD output. It did not make the release gates pass.

## 1. Initial thesis

**Tested fact.** SarifRegress compares a baseline SARIF run with a candidate run and emits a stable
JSON contract plus optional offline HTML and canonical SARIF projections. Matching is local,
deterministic, and one-to-one, with configured candidate and assignment limits. It distinguishes
correspondence from the later classification of an accepted pair as unchanged, moved, or modified.
The pre-release audit found that candidate-edge objects were materialised before the retained-edge
cap. The matcher now performs complete-graph accounting with compact descriptors and materialises
full explanations only for retained pairs; its default-global-cap stress case records peak memory.

**Interpretation.** The useful product thesis is narrower than “diff arbitrary SARIF.” It is:
accept a regression relationship only when the available evidence supports a defensible identity
claim, explain the decision, and refuse ambiguity. A missed match is costly, but a false match can
hide a new security finding or misstate a resolved one, so precision and explicit refusal take
priority.

## 2. Why the development corpus was insufficient

**Tested fact.** The development corpus covered fingerprints, line shifts, message changes,
repository-root changes, aliases, duplicate fingerprints, assignment ambiguity, new/resolved
findings, malformed input, and resource limits. It passed before the real-producer holdout was
introduced. The pre-fix holdout, with ground truth independently derived from controlled source
transformations, then produced `0 TP / 0 FP / 75 FN` under matcher v2.

**Interpretation.** A corpus written alongside an implementation is valuable for regression and
boundary tests, but it can share the implementation author's assumptions. It did not represent
three authentic producer behaviors: unresolved external URI bases, repeated low-information
redacted context, and findings with neither fingerprints nor snippets. Passing it established
internal consistency, not producer generalisation.

## 3. Independent holdout design

**Tested fact.** The holdout freezes authentic projected SARIF from Semgrep, Gitleaks, and PMD,
with 25 labelled relationships per producer. Across all three producers it contains 75 labelled
relationships and 99 ground-truth units, including new, resolved, and deliberate ambiguity cases.
Ground truth comes from controlled source transformations rather than matcher output. The v2 and
v3 reports are retained as immutable histories; later work adds deltas rather than rewriting them.
Matcher v2's first evaluation is the independent result. Because that holdout then informed v3,
v3.1, and v3.2, their figures are exposed-holdout regression evidence, not a new out-of-sample
validation.
The [hash-bound interpretation erratum](../validation/holdout/interpretation-erratum.json) records
that correction without changing historical metrics or evidence bytes.

Labels are not matcher input. The evaluator scores correspondence TP/FP/FN, post-correspondence
classification mismatch, expected/correct/incorrect labelled new and resolved counts, ambiguity
refusal, ingestion failure, and structural failure separately. The holdout report's current
“accuracy” fields do not penalise unexpected new/resolved outputs and are not full lifecycle
accuracy. This matters because an accepted relationship can be correct even when its
moved/modified label is wrong, while a run that accepts nothing can have no false positive but
still be useless.

**Interpretation.** Matcher v2 changed the question from “does the algorithm satisfy examples we
expected?” to “which failures does a pre-frozen producer corpus expose?” Later versions show
regression improvements against labels kept frozen, not fresh independent generalisation.
Immutable history prevents those improvements from erasing the original failure mode.

## 4. Matcher v2: zero of 75 relationships recovered

| Producer | TP | FP | FN | Recall | Main failure |
|---|---:|---:|---:|---:|---|
| Semgrep | 0 | 0 | 25 | `0` | Two inputs failed ingestion because `%SRCROOT%` had no safe mapping |
| Gitleaks | 0 | 0 | 25 | `0` | Repeated redacted context collapsed useful evidence into ambiguity |
| PMD | 0 | 0 | 25 | `0` | No reliable fingerprint, snippet, or other admissible identity edge |
| **Aggregate** | **0** | **0** | **75** | **`0`** | No labelled relationship accepted |

**Tested fact.** Matcher v2 reported `0 TP / 0 FP / 75 FN`, recall `0`, and F1 `0`. The report uses
the project's empty-acceptance convention of precision `1.0`; the accepted-match denominator is
zero, so this is not evidence of useful precision. Semgrep had two ingestion failures. Gitleaks
produced a large ambiguous result. PMD emitted 30 new and 30 resolved classifications instead of
continuity relationships.

**Interpretation.** “Zero false positives” was necessary but not sufficient. The version was a
valuable safety baseline because it refused unsupported claims, but it did not yet perform the
job across the holdout.

## 5. Three distinct real-producer failures

### Semgrep: URI identity before matching

Authentic Semgrep output referenced `%SRCROOT%` without defining it in `run.originalUriBaseIds`.
The matcher never reached correspondence because canonical ingestion failed. The defect was
therefore in safe input interpretation, not edge scoring.

### Gitleaks: evidence collision before assignment

Gitleaks redacts secret material. Multiple findings can consequently share low-information context
inside one producer/rule bucket. Matcher v2 treated the repeated value too uniformly, obscuring
other unique evidence and creating oversized ambiguity. The defect was collision reliability and
graph construction, not a reason to make the solver greedier or increase its limits.

### PMD: insufficient identity evidence

PMD 7.26.0 supplied sparse findings without usable producer fingerprints or embedded snippets.
Rule, path, region, and canonical message sometimes coincided, but duplicates and source movement
made those observations unsafe as identity proof. This was an evidence limitation, not an
ingestion failure.

**Interpretation.** One “real-producer compatibility” heuristic could not safely solve all
three. They sit at different layers: canonicalisation, evidence reliability, and absence of
evidence.

## 6. General URI-base mapping

**Tested fact.** Matcher v3 added schema-version-1 `uriBaseMappings`. A configuration can map a
logical base ID to a bounded safe URI. SARIF-defined bases take precedence, configured mappings
fill only missing bases, mixed SARIF/configuration chains share cycle and depth checks, unsafe or
network targets fail closed, and stable provenance does not expose an absolute checkout path.
The implementation contains no Semgrep-specific branch or `%SRCROOT%` constant.

The Semgrep holdout then ingested both inputs and recovered all 25 labelled relationships with no
false positive or ingestion failure.

**Interpretation.** The smallest safe fix was an explicit configuration contract. Guessing a base
from the current directory would have been easier to use but would make canonical identity depend
on ambient state and weaken containment.

## 7. Collision-aware evidence

**Tested fact.** Matcher v3 counts raw context and derived-fingerprint occurrences inside the
producer-family/canonical-rule bucket. Evidence is strong only when it is unique on both sides.
Duplicated values are degraded before candidate-graph construction; they cannot use region
proximity to manufacture a preferred diagonal. Exact or explicitly aliased paths can retain
bounded lower-tier candidates when another compatible signal exists. Candidate, edge, connected
component, and assignment limits were not increased.

The Gitleaks holdout recovered all 25 identity relationships with `0 FP`, while deliberate
ambiguity remained refused. Input order and asymmetric duplicate tests protect deterministic
behavior.

This fixed the tested v2 collision pattern but did not initially cover every possible conflict.
The adversarial review found that collided context could still be admitted despite a conflicting
context channel, and that a shared code-flow anchor could qualify an edge without independent
identity. Matcher v3.2 closes both paths: a context conflict vetoes collided or weak admission, and
code-flow evidence can rank only an independently admitted edge when its anchor is unique on both
input sides.

**Interpretation.** A collision is a property of an evidence value in its comparison scope, not a
property of the first endpoint that happens to use it. Computing reliability before graph
construction reduced one-to-many leakage and input-order-dependent promotion in the measured
Gitleaks pattern; it is not a proof against every conflicting-evidence topology.

## 8. Why the unsafe PMD shortcut was rejected

The proposed sparse tier required equal producer family, canonical rule, repository-relative path,
exact region, and canonical message, unique on both sides of the relevant bucket. It sounded
conservative. The holdout falsified that intuition.

| TP | FP | FN | Precision | Recall | Silently matched ambiguity endpoints |
|---:|---:|---:|---:|---:|---:|
| 5 | 5 | 20 | `0.5` | `0.2` | 4 |

**Tested fact.** Three unrelated controlled identities landed on each other's former coordinates
after line movement. Two more exact intersections paired all four endpoints in the deliberate
ambiguity set. Requiring uniqueness across the whole bucket removed the errors but recovered zero
relationships.

**Interpretation.** Exact location plus exact message is still an observation. It is not a durable
identity when similar findings move through the same coordinates. The precision gate was fixed at
`0.95`, so the result was a stop condition, not an invitation to add fixture-specific rules.

## 9. Matcher v3, v3.1, and v3.2 results

| Version | TP | FP | FN | Precision | Recall | F1 | Classification mismatches |
|---|---:|---:|---:|---:|---:|---:|---:|
| Matcher v2 | 0 | 0 | 75 | no accepted pairs | `0` | `0` | 0 |
| Matcher v3 | 50 | 0 | 25 | `1.0` | `0.666667` | `0.800000` | 5 |
| Matcher v3.1 | 50 | 0 | 25 | `1.0` | `0.666667` | `0.800000` | 0 |
| Matcher v3.2 | 50 | 0 | 25 | `1.0` | `0.666667` | `0.800000` | 0 |

**Tested fact.** Matcher v3 recovered all 25 correspondence relationships for both Semgrep and
Gitleaks: each was `25 TP / 0 FP / 0 FN`; PMD remained `0 TP / 0 FP / 25 FN`. No labelled
ambiguity was silently matched, and ingestion and structural failures were zero.

Five Gitleaks pairs had correct correspondence but were classified `modified` instead of `moved`.
The files had moved without content change, but Gitleaks included the repository-relative path in
the message. Matcher v3.1 corrected the general post-correspondence rule: only a unique, delimited
substitution of the accepted finding's own full path is treated as a location-template change.
Repeated tokens, path continuations, or extra message changes remain `modified`. The labels and
correspondence logic did not change.

**Interpretation.** Versioning v3.1 rather than rewriting v3 preserves an important distinction:
identity assignment was already right, while lifecycle classification needed a narrower general
rule. Versioning v3.2 likewise preserves that evidence history while recording a precision-safety
change whose measured correspondence and classification totals are unchanged.

## 10. Side-specific repository-context experiment

The old PMD source snapshots contained adjacent ground-truth markers and could not be used as
matcher evidence. A separate research corpus therefore froze two separately designed PMD families
before the first scored run: 19 labelled relationships, 3 new findings, 3 resolved findings, and 3
ambiguity groups covering 9 endpoints. This is controlled research designed after the legacy PMD
failure was known, not a second independent holdout. Authentic PMD 7.26.0 SARIF contains no
injected fingerprints or snippets, and an automated scanner guards against label contamination.

The research harness bound baseline SARIF only to the baseline source tree and candidate SARIF
only to the candidate tree. It tested five predeclared exact, producer-agnostic variants:

| Variant | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SARIF-only control | 0 | 0 | 19 | `1.0` by empty-acceptance convention | `0` | `0` |
| Exact-region snippet | 2 | 0 | 17 | `1.0` | `0.105263` | `0.190476` |
| Token window | 4 | 0 | 15 | `1.0` | `0.210526` | `0.347826` |
| Relative context | 9 | 0 | 10 | `1.0` | `0.473684` | `0.642857` |
| Agreement-only combination | 9 | 0 | 10 | `1.0` | `0.473684` | `0.642857` |

Family detail for the strongest standalone variant was `3 TP / 0 FP / 5 FN` in clean family A
and `6 TP / 0 FP / 5 FN` in family B. Across every variant, classification mismatches were zero;
all three labelled new and three labelled resolved selectors were present; all three ambiguity
units were refused; and ingestion and structural failures were zero. Those lifecycle fields are
labelled-selector recall, not a penalty for every additional new/resolved output: the tied best
variants emit 18 new and 17 resolved findings because ten relationships remain missed and ambiguity
endpoints remain refused.

The experiment still failed its fixed gates. The best recall, `0.473684`, was below the PMD gate
of `0.80`. The historical 75-relationship holdout remained `50 TP / 0 FP / 25 FN`, recall
`0.666667`, below the aggregate gate of `0.90`; clean relationships cannot be substituted into
that frozen universe. For the four source-backed variants, trusted corpus-tree hashes detected the
declared missing, mismatched, and swapped roots; the SARIF-only control intentionally performed no
repository preflight. Without those corpus-specific hashes, every source-backed variant failed all
three wrong-root scenarios; `relative-context` and `agreement-only-combination` also failed the
family-B mismatched-snapshot scenario. Source projection was not covered by the 1k/10k/100k matcher
benchmarks. Separate preflight and per-finding reads also leave a TOCTOU gap, and the experiment did
not prove independent single-side fallback resistance or physical identity across filesystem
aliases.

Individually authenticated role projections and `sparse-experiment-limitation/v1` preserve this
safe stop. At that stage, issue #27 still required explicit full-resource-to-stable-projection
derivation and cross-binding. The SARIF-only control preflight defect tracked in issue #28 was
corrected without changing its evidence. No composite report was promoted, and neither source nor
resource evidence was changed.

**Historical decision.** No `--baseline-repo` or `--candidate-repo` product options were added at
that evidence head, matcher v4 was not created, and the product retained the shared `--repo`
contract.

**Preview-candidate follow-up.** ADR 0004 implements an independently versioned adapter rather than
changing the generic matcher. The four all-or-nothing side-specific CLI options bind each retained
physical root to an independently supplied raw-byte digest manifest. Comment-blind method/header
and statement evidence is bound to the ordinal final filename; equal rivals and renamed files are
refused. The predeclared controlled clean profile yields `18 TP / 0 FP / 1 FN`, precision `1.0`,
recall `0.947368`, with zero labelled ambiguity auto-matched. The authenticated compositor now
implements issue #27's missing derivation; promotion and strict exact-head rerun remain separate
release steps.

## 11. Final supported evidence profile

The endorsed matcher-v3.2 evidence profile supports an automatic-correspondence release claim when
the input supplies enough independently bounded evidence to admit an edge, such as:

- a reliable producer fingerprint that is not degraded by a collision;
- reliable embedded source context, or optional token context read under the existing single,
  shared approved repository root;
- a non-colliding manifest-verified filename/lexical atom from the complete side-specific root and
  digest-manifest option set;
- explicit safe URI-base configuration that makes repository-relative path evidence resolvable,
  combined with another qualifying identity signal; or
- an explicit rule alias, still combined with qualifying path and context evidence.

Matcher v3.2 turns two review findings into explicit implementation boundaries: conflicting context
vetoes collided or weak admission, and code-flow anchors cannot admit an edge and can rank only when
unique on both input sides. Exact-head normal-mode run `30763347894` confirmed both changes on
hosted Ubuntu and Windows; the release remains blocked independently by PMD recall and the other
readiness findings.

`--repo` and configuration `repoRoot` continue to bind both inputs to one shared root. The explicit
side-specific option set is opt-in, all-or-nothing, and fail-closed; it does not alter existing
callers or configuration schema `1`.

The unsupported SARIF-only profile has all of these properties: no reliable fingerprint, no
embedded snippet, no trustworthy source snapshot, and non-unique rule/path/message/location
observations. SarifRegress deliberately leaves those findings unmatched. This is the PMD holdout
result and a documented limitation, not an ingestion error.

## 12. Determinism and security engineering

**Tested fact.** Project-owned matcher-v3 and v3.1 reports were reproduced on hosted Ubuntu and
Windows product heads, and matcher-v3.2 reports were reproduced in normal mode on exact head
`d880bd0a0495650a34ae2faa8521f170af80d7a9`. Stable output excludes ambient absolute repository
paths. The 1k, 10k, and 100k SARIF-only benchmark cells retained the configured limits and oversized
pathological buckets were refused. Ubuntu enforced its calibrated runtime and memory budgets;
Windows recorded observations and byte-identical deterministic projections without applying the
Ubuntu-calibrated runtime ceilings. Source-context projection was not benchmarked.
CI run `30763347889`, holdout run `30763347894`, determinism run `30763347908`, and benchmark run
`30763347910` all concluded success and were confirmed through the GitHub connector.

Repository context uses bounded, regular-file-only, strict-decoding reads; rejects traversal,
encoded traversal, network and UNC paths, Windows device paths, symbolic links, junctions, and
other reparse points; and fails closed if the safe platform primitive is unavailable. The context
retains the component-walked physical root for its lifetime, so later reads do not reopen a
replacement pathname. Corpus output refuses lexical and physical destinations under its input
tree, package cleanup refuses linked or reparseable managed trees, explanations are bounded, and
HTML is escaped offline output derived from stable JSON. Staged output is transactional for
ordinary failures; a hostile peer that can replace the output parent during commit remains outside
that guarantee. Matcher v3.2's
conflicting-context veto and ranking-only code-flow behavior passed the exact-head Ubuntu and
Windows product suites; the compact candidate-edge implementation still needs the final
exact-head cross-platform run before issue #22 can close.

**Interpretation.** Determinism is part of correctness because assignment ties and diagnostics can
otherwise change with input order, dictionary enumeration, platform path syntax, or checkout
location. Security is also part of the matching algorithm: accepting an unsafe source read would
turn repository contents into untrusted identity evidence.

The side-specific research result is narrower. It produced useful recall measurements, but its
root-confusion behavior without trusted hashes, read-stability gap, and missing source-projection
benchmark prevent those measurements from becoming a production guarantee.

## 13. Comparison with SARIF Multitool

Microsoft SARIF Multitool 5.5.0 was pinned as an external baseline, not treated as ground truth and
not used as a behavior target.

| Tool or producer | TP | FP | FN | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|
| SarifRegress v3.2 aggregate | 50 | 0 | 25 | `1.0` | `0.666667` | `0.800000` |
| Multitool aggregate (72 comparable) | 47 | 17 | 25 | `0.734375` | `0.652778` | `0.691177` |
| Multitool Gitleaks | 17 | 0 | 7 | `1.0` | `0.708333` | `0.829268` |
| Multitool PMD | 11 | 14 | 13 | `0.44` | `0.458333` | `0.448979` |
| Multitool Semgrep | 19 | 3 | 5 | `0.863636` | `0.791667` | `0.826087` |

Across the complete comparison units, 48 were both correct, 18 were SarifRegress-only correct, 11
were Multitool-only correct, 13 were both incorrect, and 9 were non-comparable. The PMD contrast is
the central trade-off: Multitool recovered some relationships but also produced 14 false
positives; SarifRegress accepted none and therefore preserved precision at the cost of recall.

**Interpretation.** The baseline is evidence that alternative matching behavior exists, not proof
that either tool is universally correct. Producer-specific and non-comparable semantics make
ground-truth labels and explicit categories more informative than a single head-to-head score.

## 14. Remaining limitations and release decision

The stable-channel release recommendation remains **blocked**. The `0.1.0-rc.1` preview is eligible
only after exact-head hosted verification, composite promotion, the immutable-tag run, and draft
asset inspection.

- Aggregate holdout recall is `0.666667`, below the fixed `0.90` gate.
- PMD recall is `0`, below the fixed per-producer `0.80` gate.
- The first clean source-backed experiment reached only `0.473684` recall; the later bounded
  filename/lexical preview profile reaches `0.947368` on that controlled corpus.
- The trusted profile deliberately refuses filename changes and equal lexical rivals; manifests
  authenticate exact bytes but do not establish general cross-snapshot file lineage.
- Sparse findings in the unsupported evidence profile remain new/resolved rather than automatically
  paired.
- Binary signing and independent build-byte reproducibility remain absent; the authoritative
  channel-specific inventory is `docs/release-readiness.md`.

Semgrep and Gitleaks are reproducible against the frozen exposed holdout, but those regression
results are not a second independent validation and do not justify a broad claim over all SARIF
producers. No release, tag, or package publication follows from this case study.

## 15. Interview questions and defensible trade-offs

### Why prefer a false negative to a false positive?

A false negative leaves a finding visible as new and resolved, which is noisy but reviewable. A
false positive can hide a genuinely new finding behind an unrelated baseline result. The design
therefore fixes precision at `0.95`, refuses equal optima, and reports recall shortfalls openly.

### Why not use fuzzy message matching for PMD?

Messages repeat across methods and files, and PMD's sparse evidence already collides. Fuzzy text
would enlarge the candidate graph without adding identity. The experiment obtained exact,
explainable context signals first and still missed the recall gate; fuzzy matching was a declared
stop condition.

### Why not accept the exact-location signature because it is unique?

Uniqueness was local, not semantic. Controlled findings moved into each other's old coordinates,
yielding full-experiment precision `0.5` and four silently paired ambiguity endpoints. The
counterexample directly disproved the proposed tier.

### Why separate correspondence and classification?

The five Gitleaks cases had the right endpoint pairs and the wrong moved/modified label. Changing
edge admission would have risked 25 correct identities. A narrow post-assignment classification
rule fixed the actual defect and preserved correspondence metrics.

### Why configuration for URI bases instead of inference?

An explicit mapping is bounded, reviewable, deterministic, and can fail closed. Ambient checkout
inference would make identity depend on invocation location and could bypass containment. SARIF's
own definitions still take precedence.

### Why not raise graph or assignment limits for collisions?

That would hide an evidence-quality problem behind more work. Occurrence-aware reliability removes
the tested unsafe edges before components form, preserves the configured solver limits, and keeps
deliberate ambiguity visible. Candidate scoring now uses fixed-size descriptors for the globally
bounded pair set, preserves complete-component accounting, and creates full explanation objects
only after deterministic per-finding retention.

### Why did the side-specific experiment not become matcher v4 despite zero false positives?

Precision was only one gate. Best PMD recall was `0.473684`; historical aggregate recall remained
`0.666667`; root-confusion cases failed without corpus-specific hashes; and source extraction lacked
production resource and stable-snapshot evidence. Shipping would have overstated what the
experiment proved.

### What would reopen the design?

A follow-up would need immutable or equivalently stable opened snapshots, independent one-side
fault scenarios, physical root-identity checks, a bounded source-projection benchmark, and either a
scientifically clean evaluation of the original PMD identities without marker leakage or a
separately predeclared new validation universe that does not rewrite historical results. It must
also reach PMD recall at least `0.80`, aggregate recall at least `0.90`, precision at least `0.95`,
and zero automatically matched ambiguity. Those criteria should be declared before observing the
new results.
