# GitHub code-scanning compatibility

SarifRegress provides advisory checks against the GitHub-supported SARIF subset. It is not a
complete emulator of GitHub ingestion, prioritisation, alert tracking, or display behavior.

The MVP compatibility profile is pinned as `github-supported-subset-2026-07-30` and is based on
GitHub's [SARIF support documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
and [limit troubleshooting reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/results-exceed-limit).

## Checked limits

| SARIF data | Hard maximum | Display/truncation threshold |
|---|---:|---:|
| gzip-compressed file | 10 MB | not applicable |
| runs per file | 20 | none |
| results per run | 25,000 | 5,000 |
| rules per run | 25,000 | none |
| tool extensions per run | 100 | none |
| thread-flow locations per result | 10,000 | 1,000 |
| locations per result | 1,000 | 100 |
| tags per rule | 20 | 10 |
| repository alerts | 1,000,000 | none |

The checker also reports:

- SARIF versions other than `2.1.0`;
- missing required tool, rule, message, or location values in the supported subset;
- source paths that are not repository-relative when no compatible source root is available;
- URI-scheme mismatches between absolute artifact URIs and the SARIF source root;
- source-root values outside the documented `invocations[0].workingDirectory.uri` position;
- data in secondary result locations that GitHub does not use as the primary alert location;
- absent producer partial fingerprints as guidance rather than a parse failure;
- bounded counts of known properties outside GitHub's documented supported-property subset;
- the `automationDetails.id` run-ID component that GitHub stores but does not use;
- combined driver and extension rule/tag counts for the documented per-run limits.

GitHub can receive a source root from an Actions `checkout_path`, an upload API `checkout_uri`, or
`invocations[0].workingDirectory.uri`. SarifRegress can inspect only the SARIF-provided value. A
diagnostic about a missing or unsuitable SARIF working directory therefore explains that an
uploader-supplied source root can take precedence. Same-scheme absolute URIs outside the source
root are not described as an upload rejection: GitHub documents that they remain absolute. A
scheme mismatch is described conditionally because it causes rejection only when that source root
is the one selected for the upload.

GitHub documents `primaryLocationLineHash` as the partial-fingerprint family used for alert
tracking. SarifRegress preserves all producer fingerprints and keeps its own
`sarifregress/.../vN` fingerprints in a separate namespace.

## Compressed-size evaluation

The 10 MB limit applies to the gzip payload uploaded to GitHub, not to the raw SARIF byte count.
The current file-based CLI reads raw JSON and does not control the gzip encoder or metadata that a
later uploader will use. It therefore does not synthesize an upload size or infer acceptance from
the raw size. `validate` reports `compressedUploadSizeEvaluation` as `not-evaluated` and
`compressedUploadBytes` as `null`.

The ingestion API can accept a caller-measured gzip payload size. When that fact is supplied, the
checker compares it with the pinned limit and emits `GHCS0002` if it is over the threshold. This
keeps the check bounded and avoids retaining or recompressing an input in memory.

Soft-limit diagnostics do not claim that GitHub keeps the first entries. The profile follows the
documentation: results are prioritized by severity, thread-flow locations use GitHub's documented
prioritization, and location/tag diagnostics state only the number included.

Compatibility diagnostics cite `github-supported-subset-2026-07-30` so a future documentation
change can be implemented as an explicit profile update rather than silently changing results.

This profile is intentionally finite. Its ignored-property facts cover properties that the
SarifRegress wire projection already recognizes; it does not retain arbitrary unknown JSON
properties and is not a complete emulator of GitHub validation, ingestion, prioritization, alert
deduplication, or repository state.
