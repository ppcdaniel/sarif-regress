# GitHub code-scanning compatibility

SarifRegress provides advisory checks against the GitHub-supported SARIF subset. It is not a
complete emulator of GitHub ingestion, prioritisation, alert tracking, or display behavior.

The MVP compatibility profile is pinned as `github-supported-subset-2026-07-30` and is based on
GitHub's [SARIF support documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
and [limit troubleshooting reference](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/troubleshoot-sarif-uploads/results-exceed-limit).

## Checked limits

| SARIF data | Hard maximum | Display/truncation threshold |
|---|---:|---:|
| gzip-compressed file | 10 MiB | not applicable |
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
- data in secondary result locations that GitHub does not use as the primary alert location;
- absent producer partial fingerprints as guidance rather than a parse failure.

GitHub documents `primaryLocationLineHash` as the partial-fingerprint family used for alert
tracking. SarifRegress preserves all producer fingerprints and keeps its own
`sarifregress/.../vN` fingerprints in a separate namespace.

Compatibility diagnostics cite `github-supported-subset-2026-07-30` so a future documentation
change can be implemented as an explicit profile update rather than silently changing results.
