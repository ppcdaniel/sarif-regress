# SarifRegress Architecture

**Status:** Architecture baseline for MVP implementation  
**Project name:** SarifRegress  
**Repository:** `ppcdaniel/sarif-regress`  
**CLI:** `sarif-regress`  
**Primary target:** Windows 11  
**Verification target:** Windows and Linux  
**Runtime:** .NET 10 LTS  
**Licence:** MIT  

## 1. Executive summary

SarifRegress is a CLI-first, local-first engine for comparing static-analysis findings across two SARIF 2.1.0 runs.

Its central question is:

> Does a candidate finding represent the same underlying issue as a baseline finding after paths, line numbers, messages, source context, tool versions, or producer metadata have changed?

The project is not primarily a SARIF viewer. Existing tools already validate, display, merge, or perform basic baseline matching. SarifRegress is valuable only if it provides a stronger, measurable core:

- deterministic canonicalisation;
- source-aware matching;
- conservative handling of ambiguity;
- explainable decisions;
- stable machine-readable output;
- a labelled public corpus with precision, recall, and determinism metrics.

The initial MVP compares runs from the **same producer family**. Different producers may be accepted as inputs, but cross-producer equivalence requires explicit configuration such as rule aliases. The MVP must not infer that a CodeQL result and a Semgrep result are the same issue merely because they look similar.

The architecture is a modular monolith. Matching is implemented as a pure deterministic core over canonical internal models. File parsing, repository access, reports, and CLI policy are adapters around that core.

## 2. Thesis and falsification criterion

### 2.1 Thesis

A deterministic matcher can identify the same SARIF finding across common non-semantic changes while refusing unsafe matches, and it can explain every decision in a reproducible form.

### 2.2 Earliest falsification experiment

Before HTML, packaging, broad SARIF support, or performance optimisation, create a labelled corpus of approximately 200–500 baseline/candidate result pairs covering:

- exact unchanged findings;
- inserted lines above a finding;
- repository-root changes;
- Windows and POSIX path spellings;
- explicit file rename mappings;
- missing producer fingerprints;
- duplicate producer fingerprints;
- two findings on one line;
- one-to-many and many-to-one candidate conflicts;
- message-only changes;
- malformed SARIF.

The initial thesis passes only when:

- matching precision is at least 0.95;
- matching recall is at least 0.90;
- no ambiguous case is silently auto-matched;
- JSON output is byte-identical across repeated runs;
- approved cross-platform fixtures produce byte-identical JSON on Windows and Linux;
- every match and refusal includes a structured explanation.

These thresholds are engineering targets, not claims about existing tools. If the engine cannot reach them without opaque heuristics, the project must be narrowed or stopped.

## 3. Goals

The MVP will:

1. Parse the SARIF 2.1.0 fields required for comparison.
2. Report malformed, unsupported, or unresolved structures deterministically.
3. Canonicalise comparison-relevant paths, URIs, rules, locations, messages, and selected metadata.
4. Import producer fingerprints without assuming that they are unique or reliable.
5. Derive project-namespaced fingerprints from stable evidence.
6. Compare one baseline run set with one candidate run set.
7. Produce one-to-one result matches.
8. Classify findings as:
   - `new`;
   - `unchanged`;
   - `moved`;
   - `modified`;
   - `resolved`;
   - `ambiguous`.
9. Explain the evidence, transformations, rejected alternatives, and ambiguity behind each decision.
10. Produce deterministic JSON as the primary output contract.
11. Produce optional static local HTML derived only from the JSON contract.
12. Check documented GitHub code-scanning compatibility rules and limits.
13. Run locally without a network connection.
14. Build, test, and verify from PowerShell on Windows.
15. Verify tests and deterministic outputs on Windows and Linux in GitHub Actions.

## 4. Non-goals

The MVP will not:

- provide a hosted service;
- require accounts, a database server, or cloud infrastructure;
- replace CodeQL, Semgrep, Gitleaks, PMD, or other analysers;
- implement every optional SARIF feature;
- emulate GitHub code-scanning ingestion completely;
- provide collaborative triage or issue management;
- provide a full IDE extension;
- provide a large interactive dashboard;
- create a universal cross-tool severity taxonomy;
- infer cross-producer equivalence without explicit mappings;
- use an LLM or opaque machine-learning model;
- execute repository code;
- fetch network resources from SARIF URIs;
- perform automatic source-code fixes;
- use language-specific AST or symbol extraction in the first MVP.

## 5. Existing ecosystem and differentiation

Adjacent tools already cover important parts of the space:

- GitHub code scanning uses a supported subset of SARIF and tracks alerts using rule identity and fingerprints.
- Microsoft SARIF SDK provides a comprehensive .NET object model.
- Microsoft SARIF Multitool supports validation, rewriting, URI rebasing, merging, and result matching.
- Static-analysis producers often provide their own baselining or diff-aware behaviour.
- Multiple SARIF viewers already exist.

Therefore, these are not differentiators:

- displaying SARIF;
- validating only against the JSON schema;
- merging files;
- producing a basic two-column diff;
- wrapping SARIF Multitool with a UI.

The project differentiates itself through:

1. **Explainable identity decisions.** Every decision records exact evidence and precedence.
2. **Conservative ambiguity handling.** Equal or unsafe alternatives are refused rather than resolved by input order.
3. **Cross-platform deterministic output.** The same approved input has the same output bytes.
4. **Published evaluation.** The repository reports precision, recall, F1, ambiguity, throughput, and memory against a labelled corpus.
5. **Explicit Windows path semantics.** Drive-relative, drive-absolute, UNC, URI, device-path, and repo-relative forms are distinguished.
6. **Comparison against existing baselines.** Corpus results record how SarifRegress differs from existing SARIF matching tools where practical.

## 6. Scope of producer interoperability

### 6.1 Default rule

Automatic matching is intended for baseline and candidate runs from the same producer family, allowing tool-version changes.

A producer family is identified by stable configured or normalised metadata such as:

- tool name;
- semantic tool family;
- organisation or extension identity where available;
- explicit user configuration.

### 6.2 Cross-producer matching

Cross-producer matching is disabled by default. It may be enabled only through explicit configuration, for example:

```json
{
  "ruleAliases": [
    {
      "baselineProducer": "Semgrep",
      "baselineRule": "python.lang.security.audit.eval-detected",
      "candidateProducer": "InternalScanner",
      "candidateRule": "PY-EVAL-001"
    }
  ]
}
```

An explicit alias allows two rule identities to enter the same candidate bucket. It does not guarantee a result match; location and context evidence must still qualify.

## 7. Architecture overview

```text
SARIF files + optional repository + config
                    │
                    ▼
             Parse and validate
                    │
                    ▼
          Canonicalise and enrich
                    │
                    ▼
          Build deterministic indices
                    │
                    ▼
       Generate admissible match edges
                    │
                    ▼
   Solve one-to-one connected components
                    │
                    ▼
      Classify and explain decisions
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
    Stable JSON   Static HTML  Optional SARIF
```

### 7.1 Core invariant

The matching engine must depend only on:

- canonical immutable finding models;
- immutable configuration;
- derived read-only repository evidence supplied by an adapter.

It must not depend on:

- the current time;
- random numbers;
- locale-sensitive comparisons;
- dictionary enumeration order;
- filesystem enumeration order;
- environment-specific absolute paths after canonicalisation;
- network responses;
- UI state.

## 8. Technology decisions

### 8.1 Language and runtime

Use C# on .NET 10.

Reasons:

- strong Windows tooling and PowerShell integration;
- supported Linux runtime and CI;
- excellent JSON and filesystem libraries;
- straightforward single-file packaging later;
- a mature SARIF ecosystem for comparison and interoperability;
- easy command-line verification by Codex.

Pin the SDK with `global.json`. Enable:

- nullable reference types;
- implicit usings;
- deterministic builds;
- warnings as errors for project source;
- central package management.

### 8.2 Initial libraries

- `System.Text.Json` for parsing and deterministic output.
- `System.CommandLine` for CLI parsing.
- xUnit v3 for tests.

Defer until required:

- BenchmarkDotNet;
- Microsoft SARIF SDK as a runtime dependency;
- HTML templating frameworks;
- Native AOT;
- language parsers.

The Microsoft SARIF SDK and Multitool should initially be external reference implementations and test baselines, not the core domain model.

## 9. Repository structure

```text
/
  src/
    SarifRegress.Cli/
    SarifRegress.Core/
    SarifRegress.Sarif/
    SarifRegress.Match/
    SarifRegress.Report/
  tests/
    SarifRegress.UnitTests/
    SarifRegress.IntegrationTests/
    SarifRegress.PropertyTests/
    SarifRegress.CorpusTests/
    SarifRegress.DeterminismTests/
  corpus/
    cases/
    schema/
    tools/
  benchmarks/
  docs/
    architecture.md
  scripts/
  .github/workflows/
```

### 9.1 Project-reference rules

- `SarifRegress.Core` references no application project.
- `SarifRegress.Sarif` may reference `Core` only.
- `SarifRegress.Match` may reference `Core` only.
- `SarifRegress.Report` may reference `Core` only.
- `SarifRegress.Cli` may reference all application libraries.
- No library references `Cli`.
- The matching project does not reference SARIF parsing or report projects.

These boundaries make the matching engine independently testable and prevent the SARIF wire model from leaking into domain logic.

## 10. Major components

| Component | Responsibility |
|---|---|
| `Cli` | Parse commands, compose services, map policy and failures to exit codes |
| `Core` | Domain types, diagnostics, source references, canonical primitives, output contracts |
| `SarifIngest` | Stream-parse the supported SARIF subset and preserve source pointers |
| `SarifValidation` | Structural checks, supported-subset diagnostics, GitHub compatibility checks |
| `Canonicalisation` | Path, URI, rule, message, location, and transform canonicalisation |
| `RepoContext` | Read-only bounded source lookup and context derivation |
| `Matching` | Candidate indexing, evidence evaluation, assignment, classification |
| `Explanation` | Evidence records, rejected alternatives, ambiguity and transform traces |
| `Reporting.Json` | Byte-stable JSON serialisation |
| `Reporting.Html` | Static local HTML generated only from stable JSON data |
| `SarifExport` | Optional canonicalised SARIF with project-namespaced fingerprints |
| `CorpusRunner` | Evaluate labelled cases and compute quality metrics |
| `Benchmarks` | Throughput, latency, memory, scaling, and pathological-bucket tests |

## 11. Domain model

The domain model is deliberately smaller than SARIF. It records original values, canonical values, and provenance separately.

### 11.1 Core entities

- `ComparisonInput`
- `RunIdentity`
- `ProducerIdentity`
- `RuleIdentity`
- `Finding`
- `PrimaryLocation`
- `Region`
- `CanonicalPath`
- `MessageIdentity`
- `ProducerFingerprint`
- `DerivedFingerprint`
- `ContextEvidence`
- `CodeFlowEvidence`
- `MatchEdge`
- `MatchAssignment`
- `FindingClassification`
- `DecisionTrace`
- `EvidenceRecord`
- `RejectedAlternative`
- `TransformationRecord`
- `Diagnostic`
- `SourceReference`

### 11.2 Example canonical finding

```json
{
  "findingKey": "candidate:0:1532",
  "sourceRef": {
    "input": "candidate",
    "runIndex": 0,
    "resultIndex": 1532,
    "jsonPointer": "/runs/0/results/1532"
  },
  "producer": {
    "toolName": "CodeQL command-line toolchain",
    "toolVersion": "x.y.z",
    "family": "codeql",
    "automationCategory": null
  },
  "rule": {
    "originalId": "cpp/unsafe-format-string",
    "canonicalId": "codeql/cpp/unsafe-format-string",
    "aliasApplied": false
  },
  "primaryLocation": {
    "originalUri": "file:///C:/repo/src/a.cpp",
    "canonicalUri": "repo://src/a.cpp",
    "repoRelativePath": "src/a.cpp",
    "pathKind": "repo-relative",
    "region": {
      "startLine": 120,
      "startColumn": 9,
      "endLine": 120,
      "endColumn": 24
    }
  },
  "message": {
    "originalText": "Uncontrolled format string.",
    "canonicalText": "uncontrolled format string.",
    "normalisationFlags": ["collapsed-whitespace", "invariant-case-fold"]
  },
  "fingerprints": {
    "producer": {
      "primaryLocationLineHash/v1": "..."
    },
    "derived": {
      "sarifregress/rule-path-context/v1": "..."
    },
    "reliability": {
      "primaryLocationLineHash/v1": "high"
    }
  },
  "context": {
    "snippetHash": "...",
    "tokenWindowHash": null,
    "enclosingSymbol": null
  },
  "relatedLocations": [],
  "codeFlowSummary": null,
  "lossiness": [],
  "diagnostics": []
}
```

## 12. Parsing and supported SARIF subset

The parser should stream JSON and materialise only comparison-relevant fields.

Initial supported fields include, when present:

- log `version`;
- `runs[]`;
- tool driver name, version, semantic version, rules;
- `automationDetails.id` and relevant run identity;
- artifacts and `originalUriBaseIds`;
- results;
- result `ruleId`, `ruleIndex`, message, level, kind;
- fingerprints and partial fingerprints;
- locations and physical locations;
- artifact URI, URI base ID, and artifact index;
- regions and snippets;
- related locations;
- selected code-flow and thread-flow locations;
- baseline state as source metadata only.

Unsupported optional structures should normally produce diagnostics, not failure, unless they prevent unambiguous interpretation of a required field.

All source-derived domain objects should retain a `SourceReference` with input name, run index, result index, and JSON Pointer where practical.

## 13. Canonicalisation

### 13.1 General rules

- Use ordinal, culture-invariant comparison.
- Preserve original and canonical values separately.
- Record every lossy transformation.
- Do not use current working directory unless explicitly selected as the repository root.
- Do not access network URIs.
- Do not resolve symlinks outside the approved repository root by default.

### 13.2 Path and URI rules

Canonicalisation must:

1. Resolve `artifact.index` references.
2. Resolve `uriBaseId` chains recursively with cycle and depth detection.
3. Preserve:
   - original lexical value;
   - resolved logical value;
   - canonical comparison value.
4. Convert canonical separators to `/`.
5. Collapse `.` and `..` only after a logical root is known.
6. Never permit traversal above the logical root.
7. Prefer `repo://` canonical URIs when a repository root or explicit rebase is available.
8. Keep unresolved external URIs in distinct namespaces.
9. Percent-decode only where semantically safe and record the transform.
10. Avoid case folding by default except where a configured filesystem policy permits it.

### 13.3 Windows path kinds

The model must distinguish:

- drive-absolute: `C:\repo\file.cs`;
- drive-relative: `C:file.cs`;
- root-relative: `\repo\file.cs`;
- UNC: `\\server\share\file.cs`;
- device path: `\\?\C:\repo\file.cs`;
- device UNC: `\\?\UNC\server\share\file.cs`;
- file URI: `file:///C:/repo/file.cs`;
- repository-relative: `src/file.cs`.

`C:file.cs` must never be treated as equivalent to `C:\file.cs`.

Reserved Windows names and invalid lexical forms should be retained as input data and diagnosed rather than silently rewritten into a different path.

### 13.4 Message canonicalisation

The first version may:

- normalise line endings;
- trim leading and trailing whitespace;
- collapse internal whitespace runs;
- use invariant case folding for a separate comparison form;
- preserve original punctuation;
- preserve parameter values unless an explicit producer adapter marks them unstable.

Do not initially strip numbers, file names, identifiers, or quoted values globally; those may distinguish two findings on the same line.

## 14. Fingerprints

### 14.1 Producer fingerprints

- Import all named producer fingerprints and partial fingerprints.
- Parse versioned hierarchical names when possible.
- Compare the greatest common supported version of the same family.
- Never overwrite producer fingerprints.
- Detect duplicate values inside a coarse run bucket and degrade their reliability.
- Treat missing fingerprints as absence of evidence, not an error.

### 14.2 Derived fingerprints

Derived fingerprints must:

- use a `sarifregress/.../vN` namespace;
- exclude absolute line numbers;
- exclude machine-specific absolute repository paths;
- use stable canonical rule and context evidence;
- have separately versioned algorithms;
- be reproducible across Windows and Linux for approved fixtures.

An initial algorithm may combine:

- canonical producer family;
- canonical rule identity;
- canonical repo-relative path when stable;
- normalised snippet or bounded source-context hash.

## 15. Matching pipeline

1. Parse baseline and candidate inputs.
2. Validate supported structures.
3. Resolve producer and rule identities.
4. Resolve and canonicalise locations.
5. Canonicalise messages.
6. Optionally enrich from bounded repository context.
7. Import and assess producer fingerprints.
8. Generate derived fingerprints.
9. Build coarse candidate buckets.
10. Resolve indisputable exact matches.
11. Generate remaining admissible match edges.
12. Split the bipartite graph into connected components.
13. Solve a deterministic one-to-one assignment for each component.
14. Detect equal-optimal or unsafe assignments as ambiguous.
15. Classify matched and unmatched findings.
16. Generate decision traces.
17. Produce stable output and policy exit codes.

## 16. Evidence hierarchy

Evidence is evaluated lexicographically, not as an opaque floating-point score.

| Tier | Evidence | Notes |
|---|---|---|
| `override` | Explicit user mapping | Allows bucket entry, but still records evidence |
| `exact-producer` | Same canonical rule and same reliable producer fingerprint family/version | Strongest automatic evidence |
| `exact-canonical` | Same canonical rule, canonical path, and derived context fingerprint | Used when producer fingerprints are absent or degraded |
| `strong-moved` | Same canonical rule, explicit or inferred path rebase, stable context | Intended for moved findings |
| `path-problem` | Same rule and compatible code-flow anchors | Deferred until code-flow phase |
| `weak-contextual` | Same rule bucket plus high context/message agreement | Allowed only with no equal rival |
| `refuse` | Equal best rivals or unsafe conflict | Produce `ambiguous` |

A match edge carries a deterministic decision vector such as:

```text
(
  precedenceTier,
  producerFingerprintStrength,
  pathMatchKind,
  contextAgreement,
  codeFlowAgreement,
  messageSimilarityBand,
  regionDriftBand,
  stableIdentityKey
)
```

The `stableIdentityKey` exists only to produce deterministic ordering. It must not resolve semantic equality between two otherwise equally valid assignments.

## 17. One-to-one assignment

Each baseline finding may match at most one candidate finding, and each candidate finding may match at most one baseline finding.

A greedy result-by-result matcher is prohibited because it can be order-dependent and globally suboptimal.

### 17.1 Assignment process

1. Commit indisputable exact matches whose fingerprint is reliable and unique on both sides.
2. Remove committed findings from further consideration.
3. Generate admissible edges for the remainder.
4. Split edges into connected bipartite components.
5. For each component, choose the lexicographically best maximum-cardinality one-to-one assignment.
6. When more than one assignment has the same semantic decision vector, mark the affected component ambiguous.
7. Do not resolve equal semantic assignments using result array order.
8. Record rejected edges and assignment conflicts in the decision trace.

Most components should be small due to coarse bucketing. Implement a correct bounded solver before attempting broad performance optimisation.

## 18. Classification

- **Unchanged:** High-tier match; canonical rule and logical location are stable; context is materially stable.
- **Moved:** Same issue is strongly matched, but path and/or region moved materially.
- **Modified:** Continuity is sufficient for a match, but message, context, or flow changed substantially.
- **Resolved:** Baseline finding is left unmatched after non-ambiguous assignment.
- **New:** Candidate finding is left unmatched after non-ambiguous assignment.
- **Ambiguous:** Multiple admissible rivals or assignments cannot be resolved without arbitrary choice.

These are project-level terms. Optional canonicalised SARIF export may map compatible classes to SARIF baseline states, but the richer project taxonomy must remain explicit in JSON.

## 19. Repository context

Repository context is optional and read-only.

The adapter may provide:

- whether a canonical path exists;
- a bounded snippet around a region;
- a normalised source-context hash;
- later, token windows or language-specific evidence through plugins.

Security and reproducibility rules:

- no code execution;
- no package restore;
- no language-server invocation;
- no network access;
- bounded file size and read limits;
- path must resolve inside the approved root unless explicitly allowed;
- stable newline handling;
- symlink and junction checks.

`enclosingSymbol` remains nullable and deferred. It must not be a dependency of the initial matcher.

## 20. Code flows and additional locations

For the initial MVP, the first result location is the primary location. Other locations and code-flow data are supporting evidence only.

Later code-flow support should:

- derive stable anchor signatures rather than raw full line sequences;
- use canonical path buckets and bounded context hashes;
- compare related locations as sorted sets, not array position;
- treat absent secondary data as unavailable, not contradictory;
- cap flow size and explanation output.

## 21. Configuration

Use JSON only for the MVP.

```json
{
  "schemaVersion": "1",
  "repoRoot": ".",
  "pathRebases": [
    { "from": "file:///C:/agent/_work/1/s/", "to": "repo:/" }
  ],
  "pathAliases": [
    { "baseline": "src-old/", "candidate": "src/" }
  ],
  "ruleAliases": [
    {
      "baselineProducer": "CodeQL",
      "baselineRule": "old/rule-id",
      "candidateProducer": "CodeQL",
      "candidateRule": "new/rule-id"
    }
  ],
  "matching": {
    "enableRepoContext": true,
    "snippetLinesRadius": 3,
    "allowWeakMessageSimilarity": false
  },
  "policy": {
    "failOn": ["new", "modified", "ambiguous"],
    "treatGithubIncompatibilityAsError": false
  },
  "reporting": {
    "emitCanonicalSarif": false,
    "emitHtml": true
  }
}
```

Configuration must have its own schema version and deterministic validation diagnostics.

## 22. CLI design

```text
sarif-regress compare
sarif-regress validate
sarif-regress canonicalise
sarif-regress corpus run
sarif-regress bench
```

### 22.1 Main command

```powershell
sarif-regress compare `
  --baseline baseline.sarif `
  --candidate candidate.sarif `
  --repo C:\repo `
  --config regress.config.json `
  --json-out out\report.json `
  --html-out out\report.html
```

### 22.2 Exit-code policy

Reserve stable exit-code families, for example:

- `0`: command succeeded and policy passed;
- `1`: command or input error;
- `2`: recognised command not implemented during bootstrap only;
- `3`: comparison succeeded but configured regression policy failed;
- `4`: internal invariant failure.

The final values must be documented and tested before the first public release.

## 23. JSON output contract

JSON is the source of truth. HTML must consume the same contract.

```json
{
  "outputSchemaVersion": "1",
  "tool": {
    "name": "sarif-regress",
    "version": "0.1.0"
  },
  "inputs": {},
  "summary": {
    "baselineCount": 0,
    "candidateCount": 0,
    "new": 0,
    "unchanged": 0,
    "moved": 0,
    "modified": 0,
    "resolved": 0,
    "ambiguous": 0
  },
  "findings": [
    {
      "classification": "moved",
      "candidateRef": {},
      "baselineRef": {},
      "decision": {
        "precedenceTier": "strong-moved",
        "displayConfidence": "high",
        "ambiguous": false
      },
      "evidence": [],
      "rejectedAlternatives": [],
      "transforms": [],
      "diagnostics": []
    }
  ],
  "diagnostics": [],
  "metrics": {},
  "determinism": {
    "jsonCanonicalisation": "schema-order-v1",
    "crossPlatformNormalisation": "approved-path-normalisation-v1"
  }
}
```

Every evidence item records:

- evidence kind;
- exact compared values or hashes;
- whether it came from the producer, configuration, repository, or system;
- precedence tier;
- lossiness;
- algorithm version.

## 24. Diagnostics

All stages use a uniform diagnostic shape:

```json
{
  "code": "GHCS0007",
  "severity": "warning",
  "stage": "github-compat",
  "message": "Only the first result location is used by GitHub code scanning.",
  "sourceRef": {
    "runIndex": 0,
    "resultIndex": 42,
    "jsonPointer": "/runs/0/results/42/locations"
  },
  "standardBasis": "github-supported-subset",
  "help": "Secondary locations remain available for local comparison."
}
```

Code families:

- `PARSE*`
- `SCHEMA*`
- `UNSUPPORTED*`
- `GHCS*`
- `CANON*`
- `MATCH*`
- `IO*`
- `SECURITY*`
- `INTERNAL*`

Diagnostics based on documented standards must be distinguished from project inference.

## 25. GitHub compatibility checks

The compatibility checker is advisory by default and checks only documented behaviour, including:

- supported SARIF version;
- documented supported properties;
- repository-relative source path guidance;
- fingerprint guidance;
- compressed upload size;
- documented object-count limits;
- data that GitHub ignores or truncates.

The checker must not claim to be a complete emulator of GitHub ingestion.

## 26. Determinism

Use:

- ordinal string comparisons;
- invariant culture;
- explicit stable sort keys;
- deterministic one-to-one assignment;
- UTF-8 without BOM;
- LF line endings in generated text;
- explicit JSON property order;
- fixed hash algorithms and versioned inputs;
- no timestamps in stable reports unless supplied as source data and explicitly preserved;
- no process IDs or current machine paths in stable reports;
- canonical number formatting.

Tests must compare output bytes, not merely deserialised object equality.

## 27. Security

Treat SARIF files, configuration, and source repositories as untrusted.

Required protections:

- streaming JSON parsing;
- maximum input size, nesting depth, collection size, and string length;
- bounded URI-base resolution with cycle detection;
- no network requests;
- no code execution;
- read-only source access;
- repository-root containment checks;
- symlink and junction escape protection;
- HTML escaping for all SARIF and source values;
- bounded explanation sizes;
- safe handling of invalid UTF-8 and unusual path forms;
- fail closed on invalid indexes and unresolved required references;
- no secret values in diagnostic telemetry because the MVP has no telemetry.

## 28. Testing strategy

### 28.1 Testing pyramid

| Layer | Purpose |
|---|---|
| Unit | Canonicalisation, path forms, decision vectors, diagnostics |
| Integration | Complete CLI comparisons over fixed fixtures |
| Golden | Byte-identical JSON and deterministic HTML |
| Corpus | Precision, recall, F1, ambiguity, assignment correctness |
| Property-based | Invariance under harmless transformations |
| Fuzz | Hostile JSON, paths, deep structures, huge strings |
| Benchmarks | Throughput, latency, memory, pathological buckets |

### 28.2 Corpus layout

```text
corpus/cases/rename-with-line-shift/
  baseline.sarif
  candidate.sarif
  repo/
  config.json
  labels.json
  notes.md
```

`labels.json` stores the ground-truth pairing graph, classifications, and expected ambiguity. Summary counts alone are insufficient.

### 28.3 Corpus strata

- synthetic micro-cases;
- controlled mutations of real producer output;
- negative and ambiguity cases;
- malformed and unsupported input;
- GitHub-subset compatibility cases.

### 28.4 Property invariants

- JSON property reordering does not change output.
- Harmless SARIF array reordering does not change output where ordering is not semantic.
- Equivalent Windows/POSIX path forms compare identically after approved canonicalisation.
- Blank-line insertion does not break context identity when sufficient evidence remains.
- Ignored optional SARIF properties do not change decisions.
- Input ordering does not resolve semantic ambiguity.

## 29. Benchmarks

Measure:

- parse throughput;
- canonicalisation throughput;
- compare latency;
- peak working set;
- number and size of candidate edges;
- assignment component sizes;
- explanation output size;
- cross-platform report hashes.

Datasets:

- 1,000 findings;
- 10,000 findings;
- 100,000 findings;
- pathological buckets with many findings sharing the same producer, rule, and file.

Do not add BenchmarkDotNet until functional correctness and the initial corpus are established.

## 30. Existing-tool comparison

Where practical, each corpus case may record outputs from reference tools:

```json
{
  "expected": {},
  "sarifRegress": {},
  "sarifMultitool": {},
  "differenceExplanation": "SarifRegress refused a duplicate-fingerprint collision instead of selecting by result order."
}
```

The project does not need to outperform existing tools on every case. It must clearly demonstrate additional value such as:

- explainable evidence;
- deterministic ambiguity refusal;
- explicit Windows path handling;
- stable JSON output;
- published corpus metrics.

## 31. CI and release workflow

GitHub Actions jobs:

1. `build-test`
   - `windows-latest`;
   - `ubuntu-latest`;
   - formatting, build, unit and integration tests.
2. `determinism`
   - run approved corpus on both OSes;
   - compare stable output hashes.
3. `corpus-eval`
   - precision, recall, F1, and ambiguity thresholds.
4. `bench-smoke`
   - reduced benchmark suite on pull requests.
5. `release`
   - later, publish checksummed Windows and Linux binaries.

Local and CI verification should use the same scripts where practical:

```powershell
.\scripts\verify.ps1
```

```bash
./scripts/verify.sh
```

## 32. Packaging

Packaging order:

1. normal framework-dependent .NET tool for contributors;
2. self-contained single-file Windows and Linux binaries;
3. optional Native AOT experiment after dependency and reflection audit.

Packaging is not part of Phase Alpha.

## 33. Incremental delivery phases

### Phase Alpha — falsification spike

Implement only:

- repository and solution bootstrap;
- source-reference and diagnostic contracts;
- supported-subset parsing;
- path and message canonicalisation;
- producer fingerprint import;
- one derived source-context fingerprint;
- exact producer and exact canonical tiers;
- one-to-one assignment;
- ambiguity refusal;
- stable JSON;
- initial labelled corpus.

Exclude:

- HTML;
- GitHub compatibility;
- code flows;
- token similarity;
- canonical SARIF export;
- BenchmarkDotNet;
- Native AOT;
- 100k benchmarks.

Acceptance:

- target precision and recall on initial corpus;
- zero silent ambiguous matches;
- byte-stable JSON;
- Windows/Linux determinism for approved fixtures.

### Phase Beta — production canonicalisation

Add:

- full Windows path edge cases;
- URI-base chains;
- artifact indexes;
- GitHub compatibility checks;
- stronger diagnostics;
- same-OS determinism suite.

### Phase Gamma — moved and modified results

Add:

- bounded snippets;
- context hashes;
- optional token windows;
- path aliases and rebases;
- moved/modified classification;
- expanded producer fixtures.

### Phase Delta — supporting evidence and scale

Add:

- selected code-flow evidence;
- static HTML from JSON;
- 100k-scale benchmarks;
- pathological component benchmarks.

### Phase Epsilon — export and public contracts

Add:

- optional canonicalised SARIF;
- stable config schema;
- stable output schema;
- release packaging and documentation.

## 34. First 20 implementation issues

1. Bootstrap repository, .NET solution, scripts, architecture tests, and Windows/Linux CI.
2. Define source-reference, diagnostic, severity, and stage contracts.
3. Define canonical path and path-kind value objects.
4. Add deterministic JSON writer and golden-test helper.
5. Implement streaming SARIF log/version/run reader.
6. Map the supported result subset into ingest models.
7. Resolve rule IDs and rule indexes.
8. Resolve artifact indexes.
9. Resolve URI-base chains with cycle detection.
10. Implement POSIX, URI, drive, drive-relative, UNC, and device-path canonicalisation.
11. Implement message canonicalisation.
12. Add optional bounded repository source lookup.
13. Import producer partial fingerprints and assess duplicate reliability.
14. Implement the first project-namespaced context fingerprint.
15. Implement exact producer-fingerprint match tier.
16. Implement exact canonical-context match tier.
17. Implement bipartite components and one-to-one assignment.
18. Implement ambiguity detection and refusal.
19. Emit stable comparison JSON with evidence traces.
20. Implement corpus labels, metrics, and Windows/Linux determinism workflow.

Every issue must have executable acceptance criteria and must not include work from later issues.

## 35. MVP definition of done

The MVP is done only when:

- one baseline and one candidate SARIF 2.1.0 input can be compared;
- malformed and unsupported structures produce deterministic diagnostics;
- comparison-relevant paths, rules, locations, and messages are canonicalised;
- producer and derived fingerprints remain distinct;
- absolute line numbers are not used as identity fingerprints;
- one-to-one assignment is deterministic and not greedy-order-dependent;
- findings are classified as new, unchanged, moved, modified, resolved, or ambiguous;
- no ambiguous case is silently auto-matched;
- every decision contains an explanation trace;
- JSON output is byte-identical across repeated runs;
- approved fixtures are byte-identical across Windows and Linux;
- a labelled public corpus reports precision, recall, F1, and ambiguity;
- the project meets published resource budgets;
- a static HTML report can be derived from JSON without match-engine dependencies;
- tests, corpus evaluation, and determinism run in GitHub Actions on Windows and Linux;
- build, test, lint, verify, and package commands are documented and reproducible.

## 36. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Existing tools already solve enough of the problem | High | Compare against them early; centre explainability and ambiguity |
| Matcher produces impressive metrics on unrealistic fixtures | High | Include controlled real-producer outputs and hard negative cases |
| Cross-producer matching becomes subjective | High | Same-producer default; explicit aliases only |
| Greedy matching creates order-dependent errors | High | Component-level one-to-one assignment |
| Path canonicalisation causes false equivalence | High | Typed path kinds, provenance, extensive Windows fixtures |
| Source context leaks outside repository | High | Containment checks, read limits, no execution |
| Output changes unpredictably between releases | High | Versioned schema and fingerprint algorithms |
| UI consumes project time | Medium | JSON-first; HTML deferred and read-only |
| Full SARIF model overwhelms scope | High | Explicit supported subset and diagnostics |
| Codex implements later issues prematurely | Medium | Small prompts, issue-scoped branches, mandatory diff review |

## 37. Versioning

- CLI releases use Semantic Versioning.
- Config and output JSON have independent schema versions.
- Derived fingerprints include algorithm versions.
- Additive output fields may remain in the same schema version.
- Renames, removals, or semantic changes require a schema bump.
- Matching changes that can alter classifications require release notes and corpus comparison.
- Stable output must record the matcher algorithm version.

## 38. Official references

- SARIF 2.1.0 OASIS standard: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- GitHub SARIF support: https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- Microsoft SARIF SDK and Multitool: https://github.com/microsoft/sarif-sdk
- .NET support policy: https://dotnet.microsoft.com/en-us/platform/support/policy
- System.CommandLine documentation: https://learn.microsoft.com/en-us/dotnet/standard/commandline/
- xUnit: https://xunit.net/

