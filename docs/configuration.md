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

Repository context is used only when `matching.enableRepoContext` is true. It remains read-only,
bounded by file size and snippet radius, and contained below the approved root. A missing,
escaping, symlinked, or junction path fails closed.

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

An alias is not an override pairing. Location, reliable fingerprint, or context evidence must
still qualify, and equal rivals remain ambiguous.

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
