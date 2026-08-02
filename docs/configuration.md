# Configuration

SarifRegress configuration is JSON with an independent schema version. Version `1` is described by
[`schemas/config.schema.json`](../schemas/config.schema.json). Unknown properties, invalid enum
values, conflicting mappings, and values outside a trusted bound produce deterministic
configuration diagnostics.

## Example

```json
{
  "schemaVersion": "1",
  "repoRoot": "../source",
  "uriBaseMappings": [
    {
      "id": "WORKSPACE_ROOT",
      "uri": "repo:/"
    }
  ],
  "pathRebases": [
    {
      "from": "file:///C:/agent/_work/1/s/",
      "to": "repo:/"
    }
  ],
  "pathAliases": [
    {
      "baseline": "src-old/",
      "candidate": "src/"
    }
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
    "enableTokenWindows": false,
    "allowWeakMessageSimilarity": false,
    "pathCaseSensitivity": "sensitive"
  },
  "policy": {
    "failOn": [
      "new",
      "modified",
      "ambiguous"
    ],
    "treatGithubIncompatibilityAsError": false
  },
  "reporting": {
    "emitCanonicalSarif": false,
    "emitHtml": false
  },
  "limits": {
    "maximumInputBytes": 268435456,
    "maximumCandidatePairEvaluationsPerFinding": 256,
    "maximumCandidatePairEvaluations": 1000000,
    "maximumAssignmentSideSize": 12
  }
}
```

Omitted sections use deterministic defaults.

## Repository root

`repoRoot` is optional. If it is relative, it is resolved against the configuration file's
directory, never the process current directory. `--repo` is resolved against the invocation
directory and overrides `repoRoot`.

Both inputs use this one shared approved root. Configuration schema `1` has no side-specific root
fields, and the CLI has no `--baseline-repo` or `--candidate-repo` options. The clean sparse-SARIF
experiment did not change that contract.

Repository context is used only when `matching.enableRepoContext` is true. It remains read-only,
bounded by file size and snippet radius, and contained below the approved root. A missing,
escaping, symlinked, or junction path fails closed.

## External URI bases

`uriBaseMappings` explicitly define logical bases that an input references but does not define in
`run.originalUriBaseIds`. Each entry has an ordinal `id`, a directory-form `uri`, and optionally a
parent `uriBaseId`. A configured definition fills only a missing base: a valid SARIF-defined base
with the same identifier always wins and is never silently replaced.

Root targets are limited to `repo:/`, local POSIX or drive-absolute directories, and hostless local
`file:` directories. A child target must be repository-relative and end in a directory separator.
UNC, network, authority-bearing repository URIs, queries, fragments, control characters, and parent
traversal are rejected. References remain lexical; SarifRegress never fetches a URI. Unknown bases,
cycles, and chains deeper than 32 continue to fail closed. Successful use records a
`configured-uri-base` transformation with algorithm
`sarifregress/configured-uri-base/v1` in the finding explanation. The record identifies the
configured logical base but omits its raw target, so equivalent local roots do not expose machine
paths or make stable reports platform-specific.

Resolving an artifact through `uriBaseMappings` establishes a safe logical path; it is not identity
proof and cannot admit a correspondence by itself. Matching still requires another qualifying
fingerprint or context signal.

## Path rebases and aliases

`pathRebases` map one logical URI/path prefix to another namespace, commonly an agent checkout URI
to `repo:/`.

`pathAliases` declare a baseline/candidate path-prefix relationship, commonly an explicit rename.
They permit stronger moved evidence but do not guarantee a match.

Both mapping types:

- match complete path-segment prefixes only;
- use the longest matching prefix;
- reject equal-length conflicting mappings;
- preserve a transformation record;
- do not allow traversal above a known logical root.

Path comparison is case-sensitive by default. `ascii-insensitive` is an explicit filesystem policy
and folds ASCII only; it is not inferred from the host operating system.

## Rule aliases

`ruleAliases` allow two producer/rule identities to enter the same candidate bucket. This is
required for cross-producer matching and may also describe a rule rename within one producer.
Producer fields use the same collision-resistant resolution as ingested SARIF tool names:
the closed CodeQL/Semgrep allowlist is case-insensitive, while every other producer name is exact,
ordinal, and case-sensitive. A display-only `producerFamily` value is not a wildcard.

An alias is not an override pairing. Cross-producer candidates still require both a qualifying path
and exact context evidence; a reliable fingerprint alone does not qualify them, and equal rivals
remain ambiguous.

## Matching

| Field | Default | Meaning |
|---|---:|---|
| `enableRepoContext` | `true` | Permit bounded context reads when a repository root is selected |
| `snippetLinesRadius` | `3` | Source lines requested on either side, within the trusted maximum |
| `enableTokenWindows` | `false` | Enable bounded token-window evidence |
| `allowWeakMessageSimilarity` | `false` | Permit the weak contextual tier |
| `pathCaseSensitivity` | `sensitive` | Ordinal sensitive or explicit ASCII-insensitive policy |

Missing evidence is unavailable, not contradictory. `enclosingSymbol` is not required by the MVP
matcher.

Automatic correspondence is supported when there is a reliable non-colliding producer fingerprint;
reliable embedded source context or bounded token context from the shared root; or safe URI-base
resolution combined with another qualifying identity signal. Explicit rule aliases still require
qualifying path and context evidence. When there is no reliable fingerprint, no embedded snippet,
no trusted source snapshot, and only non-unique rule/path/message/location evidence, SarifRegress
leaves findings unmatched. Missing source evidence never promotes path or message coincidence.
This is the endorsed pre-release evidence profile. Matcher v3.2 makes its two reviewed admission
boundaries implementation invariants: conflicting context vetoes collided or weak admission, and
code-flow anchors cannot admit an edge. Exact-head hosted product tests on Ubuntu and Windows cover
both boundaries. Outputs outside the supported profile are still not release-backed claims.

`enableTokenWindows` opts into repository-backed `token-window/v1` evidence. The adapter derives a
bounded sequence of terms around the finding region after normalising whitespace and ignoring
blank-line-only movement. It remains constrained by `maximumRepositoryFileBytes`,
`maximumStringCharacters`, and `maximumTokenWindowTerms`. If a region has too many terms or one
term is too long, the evidence is omitted with stable diagnostic `CANON0011` or `CANON0012`
respectively; SarifRegress does not truncate an arbitrary prefix.

## Regression policy

`policy.failOn` accepts `new`, `unchanged`, `moved`, `modified`, `resolved`, and `ambiguous`. The
default is:

```json
["new", "modified", "ambiguous"]
```

The comparison report is produced before this policy is evaluated. A listed classification returns
exit `3`, allowing CI to retain the complete explanation.

`treatGithubIncompatibilityAsError` promotes advisory warnings from the pinned GitHub compatibility
profile into policy failure. It does not make SarifRegress a complete GitHub ingestion emulator.

## Reporting

`emitCanonicalSarif` and `emitHtml` record projection preferences for composed callers. CLI output
locations remain explicit: SarifRegress never invents a filesystem destination. Use `--html-out`
or `--sarif-out` when a file is required.

JSON remains the source of truth. HTML and canonical SARIF cannot alter matching decisions.

## Trusted limits

Every field in `limits` may lower a built-in ceiling for a particular invocation. Untrusted
configuration cannot raise the trusted bootstrap ceiling. The complete defaults are recorded in
[ADR 0001](decisions/0001-mvp-determinism-security-and-matching-policy.md) and
[resource-budgets.md](resource-budgets.md).

Important ceilings include:

- 256 MiB input;
- JSON depth 128;
- 250,000 rules, artifacts, or results per run;
- 4 MiB per string and repository source file;
- URI-base depth 32;
- 256 coarse pairs on either side of one finding;
- 1,000,000 coarse pairs per comparison;
- 64 retained candidate edges per finding;
- exact assignment components of at most 12 findings per side.

Limits are enforced before unbounded materialisation or semantic scoring. A pair budget does not
truncate the input and score an arbitrary prefix.
