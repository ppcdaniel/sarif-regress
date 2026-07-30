# GitHub code-scanning supported-subset case

This synthetic fixture is constrained to the property subset documented in
GitHub's primary
[`SARIF support for code scanning`](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
reference: SARIF 2.1.0, one tool driver and rule, a result level and text
message, a repository-relative physical location, and a
`primaryLocationLineHash` partial fingerprint.

The fixture is deliberately small and below the limits documented by GitHub's
primary
[`code-scanning REST reference`](https://docs.github.com/en/rest/code-scanning/code-scanning#about-code-scanning).
It is an offline profile check, not a claim that an upload was performed.

The explicit empty diagnostic expectation means the compatibility projection
must emit no advisories for either input. The selected explanation golden also
asserts that the GitHub line hash remains producer evidence and yields a
deterministic exact-producer match.
