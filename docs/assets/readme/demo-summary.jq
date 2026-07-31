"baseline \(.summary.baselineCount) · candidate \(.summary.candidateCount) · moved \(.summary.moved) · new \(.summary.new) · resolved \(.summary.resolved) · ambiguous \(.summary.ambiguous)",
(
  .findings[]
  | "\(.classification | ascii_upcase)  \(.candidate.canonicalRule)  \(.baseline.region.startLine) → \(.candidate.region.startLine)  \(.decision.displayConfidence) · \(.decision.precedenceTier)"
)
