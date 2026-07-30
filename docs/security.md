# Security model

SarifRegress treats SARIF logs, configuration, corpus labels, and repository source as untrusted
data. Comparison is local and read-only.

## Trust boundaries

SarifRegress does not:

- execute repository code, build scripts, package managers, language servers, or analysers;
- make network requests or dereference network URIs found in SARIF;
- write inside the inspected repository unless the user explicitly selects an output path there;
- resolve a source path outside the explicitly approved repository root;
- include source text, absolute machine paths, secrets, or environment data in diagnostics by
  default.

## Default bounds

The exact limits are versioned in
[ADR 0001](decisions/0001-mvp-determinism-security-and-matching-policy.md). Important defaults
include a 256-MiB input limit, JSON depth 128, 250,000 results per run, a 4-MiB repository-file
read limit, URI-base depth 32, and exact assignment components of at most 12 findings per side.

Limit violations are deterministic. A violation that prevents safe identity resolution invalidates
the affected finding or command. A component too large for exact assignment is refused as
ambiguous; SarifRegress does not substitute a heuristic assignment.

## Repository containment

Repository context is optional. Paths are first canonicalised lexically, then mapped to a
repository-relative path. The adapter rejects rooted, parent-traversing, symlink, or junction paths
that escape the approved root. Reads are bounded by file size and snippet radius. Newlines are
normalised before hashing.

## Generated output

JSON and HTML writers escape all source-derived values. The HTML report is a static offline
projection of the stable JSON contract and includes a restrictive Content Security Policy. It does
not load scripts, styles, fonts, images, or other resources from the network.

## Reporting a vulnerability

Do not include exploit payloads, repository secrets, or private SARIF files in a public issue.
Contact the repository owner privately through the security-reporting mechanism shown by GitHub
for the repository.
