# Security policy

SarifRegress is pre-release. No version is currently published or supported as a stable release.
Security fixes are developed on the active repository branches and require the same review and
verification gates as other changes.

| Version or channel | Security support |
|---|---|
| Unreleased source branches | Best-effort development fixes; no compatibility or response SLA |
| Published package, executable, or tag | None exists |

## Reporting a vulnerability

Do not open a public issue containing exploit details, private SARIF, repository source, secrets,
credentials, local paths, or identifying customer data.

1. Open the repository's
   [private security-advisory form](https://github.com/ppcdaniel/sarif-regress/security/advisories/new)
   and use **Report a vulnerability** if GitHub Private Vulnerability Reporting is available.
2. If that control is unavailable, open a public issue containing only the sentence that you need
   private security coordination and a non-sensitive description of the affected surface. Wait for
   the repository owner to establish a private channel before sending technical details.
3. Include the affected commit or version, operating system, input class, observed impact, and a
   minimal redacted reproduction only in that private channel.

The repository does not currently promise a response or remediation SLA. Do not infer one. The
owner should acknowledge the report privately, agree on disclosure timing, and record a supported
workaround before any public disclosure.

## In scope

- escaping the approved repository root, including traversal, symlink, junction, device, UNC, or
  network-path behavior;
- reading from the wrong baseline/candidate source snapshot;
- executing repository or SARIF-controlled code, commands, or network requests;
- unbounded SARIF/configuration/corpus parsing or candidate-graph work;
- unsafe ambiguity that creates a false identity match;
- source, secret, machine-path, hostname, or environment disclosure in JSON, HTML, SARIF,
  diagnostics, or workflow artifacts;
- HTML injection or weakening of the offline Content Security Policy;
- destructive or aliased output behavior, including overwriting an input;
- archive-extraction traversal or unsafe producer-capture downloads; and
- package, checksum, release-workflow, or dependency-integrity failures.

Questions about expected matcher recall without a security boundary violation are ordinary bug or
research reports, but they must still use redacted fixtures.

## Security model

The product is local and read-only with respect to analysed source. It does not execute repository
code, restore repository dependencies, run analysers, dereference SARIF network URIs, send
telemetry, or make product network requests. Parsing, repository reads, candidate graphs,
explanations, and output are bounded. Repository context uses OS-specific handle-relative no-link
opens and accepts only regular files. JSON/HTML escape source-derived values, and HTML is an offline
projection of the stable JSON contract.

These controls do not make all inputs safe in all local threat models. Known release-blocking
limitations include:

- the repository root itself is reopened between reads rather than retained as one immutable root
  handle;
- collided context may be admitted when another context channel conflicts;
- code-flow anchors can qualify an edge without independent identity;
- full candidate-edge objects are materialised before the retained-edge cap;
- `corpus run --json-out` can select a corpus input path;
- packaging cleanup can follow an `artifacts` symlink or junction; and
- transactional output has a hostile-parent TOCTOU window even though ordinary alias and rollback
  cases are handled.

Separate baseline/candidate repository roots are research-only and are not shipped. Sparse SARIF
without reliable fingerprints, embedded snippets, trusted source snapshots, and another qualifying
identity signal is unsupported and intentionally refused. A unique exact
rule/path/region/message observation is not generally sufficient identity evidence.

See `docs/security.md` for the complete input, repository, output, and resource model, and
`docs/release-readiness.md` for current blocking dispositions.

## Disclosure and release handling

Security fixes must not weaken precision, ambiguity refusal, path containment, graph limits, or
determinism to make a benchmark pass. Before publishing a fix, run exact-head Ubuntu and Windows
verification, holdout validation, determinism, affected resource tests, and package smoke. If a
published asset is affected, follow the rollback procedure in `docs/release-readiness.md`; never
replace bytes behind an existing checksum or retarget a release tag.
