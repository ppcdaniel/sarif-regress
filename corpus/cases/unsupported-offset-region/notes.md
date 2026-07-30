# Supported fallback for offset-based regions

This synthetic unsupported-subset case supplies both a normal line-and-column
region and SARIF `charOffset`/`charLength`. SarifRegress deliberately retains
the line anchor, ignores the offset fields, and emits the exact
`UNSUPPORTED0101` warning on each logical input.

The labels assert the complete diagnostic set and a selected explanation
golden. This distinguishes a deterministic, loss-aware fallback from either
silently consuming unsupported offsets or rejecting an otherwise usable
finding.
