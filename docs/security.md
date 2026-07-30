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
read limit, URI-base depth 32, 256 coarse candidate pairs per finding, 1,000,000 coarse pairs per
comparison, and exact assignment components of at most 12 findings per side.

Limit violations are deterministic. A violation that prevents safe identity resolution invalidates
the affected finding or command. A component too large for exact assignment is refused as
ambiguous; SarifRegress does not substitute a heuristic assignment.

Configuration may lower a built-in ceiling but cannot raise the trusted bootstrap ceiling. Parser
collection limits are enforced while JSON tokens are read, before an oversized subtree is
materialised. Known, unsupported, and future SARIF/configuration subtrees all use the same bounded
depth, string, object-property, and array traversal. Corpus labels are byte-capped and token-parsed
under those bounds before label collections are created. Candidate-pair budgets are preflighted
before evidence scoring; SarifRegress never scores a truncated prefix.

## Repository containment

Repository context is optional. Paths are first canonicalised lexically, then mapped to a
repository-relative path. The adapter rejects rooted, parent-traversing, symlink, or junction paths
that escape the approved root. The source file is opened relative to an anchored repository
directory handle: Linux uses `openat2` with beneath/no-link resolution and Windows uses a relative
segment-by-segment `NtCreateFile` walk. Every Windows segment is opened relative to the retained
parent handle with `FILE_OPEN_REPARSE_POINT`, then rejected by handle if it is a reparse point or
has the wrong directory/file type. The returned file handle, not a later pathname lookup, is the
only object read. If the operating system cannot provide that containment primitive, repository
context fails closed with `SECURITY0004`; it does not fall back to pathname rechecks.
Only regular files are accepted; directories, devices, sockets, and named pipes fail with
`SECURITY0005` before any content read. Reads are bounded by file size and snippet radius. Newlines
are normalised before hashing.

The native Linux containment path currently supports x64 and Arm64 kernels that expose `openat2`
and `statx`. Other Linux architectures and older kernels fail closed with `SECURITY0004`.

Optional `token-window/v1` evidence is enabled only by
`matching.enableTokenWindows`. It normalises whitespace and ignores blank-line-only movement, but
never removes its safety bounds: repository reads obey `maximumRepositoryFileBytes`, individual
terms obey `maximumStringCharacters`, and a region obeys `maximumTokenWindowTerms`. Exceeding the
last two limits omits token evidence with deterministic `CANON0011` or `CANON0012` diagnostics
instead of using a truncated prefix.

## Generated output

JSON and HTML writers escape all source-derived values. The HTML report is a static offline
projection of the stable JSON contract and includes a restrictive Content Security Policy. It does
not load scripts, styles, fonts, images, or other resources from the network.

Canonical SARIF is a separate escaped projection. Multi-file CLI outputs are staged and committed
transactionally, cannot select an input path, and cannot select the same output path twice.
Existing parent-directory symbolic links and junctions are resolved when comparing destination
identities. A final output link is replaced rather than followed. If rollback cannot restore an
original destination, its recoverable sibling backup is retained instead of being deleted.

## Reporting a vulnerability

Do not include exploit payloads, repository secrets, or private SARIF files in a public issue.
Contact the repository owner privately through the security-reporting mechanism shown by GitHub
for the repository.
