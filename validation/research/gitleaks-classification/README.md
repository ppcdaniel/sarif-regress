# Gitleaks classification mismatch analysis

This record explains the five frozen matcher-v3 correspondence decisions that
were correct but were reported as `modified` instead of the labelled `moved`.
The labels were not changed. The source transformation is an unchanged file
move, established independently by the capture plan and identical source-file
hashes. Matcher correspondence, edge admission, scoring, and assignment are
also unchanged.

The general defect was in post-correspondence classification. Gitleaks includes
the repository-relative location in its message, so the directory rename made
the canonical messages unequal. The old classifier treated any message delta as
a content modification before considering the path move.

The correction recognizes only a unique, delimited substitution of each
accepted finding's own full repository-relative path. It runs after assignment
and emits a bounded transformation hash under
`sarifregress/message-location-template/v1`. Extra message text, repeated or
embedded path tokens, and path continuations fail closed as `modified`.

Because the observable classifications change, the corrected product reports
`sarifregress/matcher/v3.1`. The global `v3` identifier and its history remain
reserved for the frozen behavior documented here; matcher v4 remains gated on
the separate sparse-SARIF experiment.

[`analysis.json`](analysis.json) contains the case-level evidence. The frozen
matcher-v3 report remains immutable; this research record points to its exact
SHA-256.
