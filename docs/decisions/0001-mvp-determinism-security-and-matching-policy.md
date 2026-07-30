# ADR 0001: MVP determinism, security, and matching policy

- **Status:** Accepted
- **Date:** 2026-07-30
- **Scope:** MVP implementation tracked by Issue #3

## Context

The architecture defines conservative matching and bounded processing but intentionally leaves
several concrete limits and tie-breaking details to implementation. Parser, canonicalisation,
matching, reporting, corpus, and benchmark work need one shared policy before they can evolve
independently.

## Decision

### Resource limits

The default untrusted-input limits are:

| Resource | Limit |
|---|---:|
| Input bytes per SARIF or configuration file | 256 MiB |
| JSON nesting depth | 128 |
| Runs per SARIF log | 64 |
| Rules, artifacts, or results per run | 250,000 |
| Locations or related locations per result | 1,000 |
| Code flows per result | 100 |
| Thread-flow locations per result | 10,000 |
| UTF-16 characters per string | 4 MiB |
| URI-base recursion depth | 32 |
| Repository source file bytes | 4 MiB |
| Configurable snippet radius | 0–20 lines |
| Token-window terms | 256 |
| Candidate edges retained per finding | 64 |
| Coarse candidate pairs evaluated per finding | 256 |
| Coarse candidate pairs evaluated per comparison | 1,000,000 |
| Rejected alternatives emitted per decision | 100 |
| Exactly solved component | at most 12 findings per side |

Limit failures produce deterministic diagnostics and fail closed when the affected structure is
required for identity. Oversized assignment components are refused as ambiguous rather than
approximated.

### Canonical bytes and hashes

Stable text is UTF-8 without a byte-order mark and uses LF line endings. Derived fingerprints use
SHA-256 over a versioned, length-prefixed sequence of UTF-8 fields. Length prefixes prevent
concatenation ambiguity. Hashes are lowercase hexadecimal.

The first derived fingerprint is `sarifregress/rule-path-context/v1`. Its fields are producer
family, canonical rule, canonical repository-relative path when available, and bounded context
hash. Absolute line numbers and machine-specific repository roots are excluded.

### Paths and aliases

Path parsing is lexical and independent of the host operating system. Comparisons are
case-sensitive by default. A configuration may explicitly request ASCII case-insensitive path
comparison for a known filesystem policy.

Rebases and aliases match only complete path-segment prefixes. The longest matching prefix wins;
equal conflicting prefixes are a configuration error. Relative configuration paths are resolved
against the configuration file directory, never the process current directory.

Only RFC 3986 unreserved percent-encoded bytes are decoded automatically. Separators and reserved
characters remain encoded. Traversal above a known logical root is rejected.

### Fingerprints and candidate buckets

The coarse automatic bucket key is canonical producer family plus canonical rule identity.
Cross-producer bucket entry requires an explicit rule alias. Producer fingerprint names use a
terminal `/vN` version when present; the greatest common numeric version within the same family is
compared. Duplicate name/value pairs inside a run-and-rule bucket are degraded and cannot produce
an indisputable exact match.

Candidate-pair limits are checked before semantic edge scoring. Per-finding limits apply to both
outgoing baseline pairs and incoming candidate pairs. Exceeding a per-finding or comparison-wide
limit refuses the unresolved comparison as ambiguous; it never scores a truncated prefix.

### Assignment and ambiguity

Assignment maximises cardinality first. Among equal-cardinality assignments it compares the
descending multiset of semantic decision vectors lexicographically. Stable finding keys order
work and output only; they are excluded from semantic equality.

If two different assignments have the same semantic objective, every finding in that connected
component is classified as ambiguous and no edge in the component is committed. Unaffected
components remain independently matchable.

### Classification

For an accepted continuity match:

1. a material message or source-context change is `modified`;
2. otherwise a canonical path or region change is `moved`;
3. otherwise the finding is `unchanged`.

Unmatched findings from non-ambiguous components are `resolved` on the baseline side and `new` on
the candidate side. Refused component members are `ambiguous`.

### Stable report policy

Reports expose logical input labels, never ambient absolute paths. Arrays are explicitly sorted
by schema-defined ordinal keys. Diagnostics sort by stage, code, source pointer, and message.
Unknown additive input properties do not affect decisions. No timestamp is generated.

HTML is rendered by deserialising the stable JSON contract, not by calling the match engine.
Canonical SARIF export is a separate projection from canonical findings.

### Quality and resource budgets

The labelled Alpha corpus contains 200–500 result pairs and must report:

- precision of at least 0.95;
- recall of at least 0.90;
- zero silently matched labelled ambiguity;
- byte-identical approved output on Windows and Linux.

The pull-request benchmark smoke uses 1,000 findings and a 10-second/512-MiB advisory budget on a
standard GitHub-hosted runner. The full published benchmark includes 1,000, 10,000, and 100,000
findings with a 60-second/1-GiB target for 100,000 findings. Wall-clock budgets are reported, while
deterministic operation and allocation bounds are the non-flaky CI gates.

## Consequences

- Large ambiguous buckets are conservative refusals rather than potentially wrong heuristic
  matches.
- Cross-platform output is independent of host path APIs and locale.
- Future algorithm changes that alter classifications require a matcher-version change and corpus
  comparison.
- Limits can become configuration fields later, but relaxing them must preserve bounded behavior.
