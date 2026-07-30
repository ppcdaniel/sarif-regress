import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const corpusRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..");
const casesRoot = path.join(corpusRoot, "cases");

const stableJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const findingKey = (side, index) => `${side}:0:${index}`;
const pair = (index, classification) => ({
  baselineKey: findingKey("baseline", index),
  candidateKey: findingKey("candidate", index),
  classification,
});

const sarif = (caseName, results) => ({
  version: "2.1.0",
  $schema:
    "https://json.schemastore.org/sarif-2.1.0.json",
  runs: [
    {
      automationDetails: {
        id: `corpus/${caseName}`,
      },
      tool: {
        driver: {
          name: "SarifRegress Corpus Analyzer",
          semanticVersion: "1.0.0",
        },
      },
      results,
    },
  ],
});

const result = ({
  rule = "CORPUS001",
  message,
  uri,
  line,
  snippet,
  fingerprint,
}) => {
  const value = {
    ruleId: rule,
    message: {
      text: message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri,
          },
          region: {
            startLine: line,
            startColumn: 1,
            endLine: line,
            endColumn: 8,
            snippet: {
              text: snippet,
            },
          },
        },
      },
    ],
  };
  if (fingerprint !== undefined) {
    value.partialFingerprints = {
      "primaryLocationLineHash/v1": fingerprint,
    };
  }

  return value;
};

const labels = ({
  pairs = [],
  expectedAmbiguous = [],
  expectedResolved = [],
  expectedNew = [],
  expectedInvalidInputs = [],
  expectedDiagnostics,
  expectedExplanations,
}) => {
  const value = {
    schemaVersion: "1",
    pairs,
    expectedAmbiguous,
    expectedResolved,
    expectedNew,
    expectedInvalidInputs,
  };
  if (expectedDiagnostics !== undefined) {
    value.expectedDiagnostics = expectedDiagnostics;
  }

  if (expectedExplanations !== undefined) {
    value.expectedExplanations = expectedExplanations;
  }

  return value;
};

const write = (filePath, content) => {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, { encoding: "utf8" });
};

const writeCase = ({
  name,
  baseline,
  candidate,
  caseLabels,
  notes,
  config,
  rawBaseline,
  rawCandidate,
}) => {
  const caseRoot = path.join(casesRoot, name);
  write(
    path.join(caseRoot, "baseline.sarif"),
    rawBaseline ?? stableJson(sarif(name, baseline)));
  write(
    path.join(caseRoot, "candidate.sarif"),
    rawCandidate ?? stableJson(sarif(name, candidate)));
  write(path.join(caseRoot, "labels.json"), stableJson(caseLabels));
  write(path.join(caseRoot, "notes.md"), `${notes.trim()}\n`);
  if (config !== undefined) {
    write(path.join(caseRoot, "config.json"), stableJson(config));
  }
};

const indexed = (count, factory) =>
  Array.from({ length: count }, (_, index) => factory(index));
const pad = (index) => index.toString().padStart(3, "0");

writeCase({
  name: "stable-identities",
  baseline: indexed(35, (index) =>
    result({
      message: `Stable defect ${pad(index)}`,
      uri: `src/stable-${pad(index)}.cs`,
      line: 20 + index,
      snippet: `dangerous_call_${pad(index)}();`,
      fingerprint: `stable-${pad(index)}`,
    })),
  candidate: indexed(35, (index) =>
    result({
      message: `Stable defect ${pad(index)}`,
      uri: `src/stable-${pad(index)}.cs`,
      line: 20 + index,
      snippet: `dangerous_call_${pad(index)}();`,
      fingerprint: `stable-${pad(index)}`,
    })),
  caseLabels: labels({
    pairs: indexed(35, (index) => pair(index, "unchanged")),
  }),
  notes: `
# Stable identities

Thirty-five distinct findings retain rule, path, region, message, source snippet,
and unique producer fingerprint identity.
`,
});

writeCase({
  name: "line-shifts",
  baseline: indexed(35, (index) =>
    result({
      message: `Shifted defect ${pad(index)}`,
      uri: `src/shift-${pad(index)}.cs`,
      line: 30 + index,
      snippet: `shift_sensitive_${pad(index)}();`,
      fingerprint: `shift-${pad(index)}`,
    })),
  candidate: indexed(35, (index) =>
    result({
      message: `Shifted defect ${pad(index)}`,
      uri: `src/shift-${pad(index)}.cs`,
      line: 130 + index,
      snippet: `shift_sensitive_${pad(index)}();`,
      fingerprint: `shift-${pad(index)}`,
    })),
  caseLabels: labels({
    pairs: indexed(35, (index) => pair(index, "moved")),
  }),
  notes: `
# Inserted lines

Each candidate region moves down by one hundred lines while producer identity,
path, message, and bounded source evidence remain stable.
`,
});

writeCase({
  name: "repository-root-changes",
  baseline: indexed(25, (index) =>
    result({
      message: `Rebased defect ${pad(index)}`,
      uri: `file:///C:/old-agent/work/repo/src/root-${pad(index)}.cs`,
      line: 40 + index,
      snippet: `root_independent_${pad(index)}();`,
    })),
  candidate: indexed(25, (index) =>
    result({
      message: `Rebased defect ${pad(index)}`,
      uri: `file:///opt/new-agent/work/repo/src/root-${pad(index)}.cs`,
      line: 40 + index,
      snippet: `root_independent_${pad(index)}();`,
    })),
  caseLabels: labels({
    pairs: indexed(25, (index) => pair(index, "unchanged")),
  }),
  config: {
    schemaVersion: "1",
    pathRebases: [
      {
        from: "file:///C:/old-agent/work/repo/",
        to: "repo:/",
      },
      {
        from: "file:///opt/new-agent/work/repo/",
        to: "repo:/",
      },
    ],
  },
  notes: `
# Repository-root and platform spelling changes

Windows file URIs from an old worker and POSIX file URIs from a new worker are
explicitly rebased to the same repository-relative namespace. No producer
fingerprints are present, so canonical path and embedded source context carry
identity.
`,
});

writeCase({
  name: "explicit-renames",
  baseline: indexed(25, (index) =>
    result({
      message: `Renamed defect ${pad(index)}`,
      uri: `src-old/component-${pad(index)}.cs`,
      line: 50 + index,
      snippet: `rename_anchor_${pad(index)}();`,
    })),
  candidate: indexed(25, (index) =>
    result({
      message: `Renamed defect ${pad(index)}`,
      uri: `src/component-${pad(index)}.cs`,
      line: 50 + index,
      snippet: `rename_anchor_${pad(index)}();`,
    })),
  caseLabels: labels({
    pairs: indexed(25, (index) => pair(index, "moved")),
  }),
  config: {
    schemaVersion: "1",
    pathAliases: [
      {
        baseline: "src-old/",
        candidate: "src/",
      },
    ],
  },
  notes: `
# Explicit file rename mapping

An explicit path-prefix alias connects twenty-five renamed source files. Stable
embedded context remains mandatory; the alias alone is not treated as proof.
`,
});

writeCase({
  name: "missing-fingerprints",
  baseline: indexed(30, (index) =>
    result({
      message: `Fingerprint-free defect ${pad(index)}`,
      uri: `src/no-fingerprint-${pad(index)}.cs`,
      line: 60 + index,
      snippet: `derived_identity_${pad(index)}();`,
    })),
  candidate: indexed(30, (index) =>
    result({
      message: `Fingerprint-free defect ${pad(index)}`,
      uri: `src/no-fingerprint-${pad(index)}.cs`,
      line: 60 + index,
      snippet: `derived_identity_${pad(index)}();`,
    })),
  caseLabels: labels({
    pairs: indexed(30, (index) => pair(index, "unchanged")),
  }),
  notes: `
# Missing producer fingerprints

Thirty distinct findings deliberately omit all producer fingerprints. The
project-namespaced rule/path/context fingerprint supplies exact canonical
identity.
`,
});

writeCase({
  name: "duplicate-fingerprints",
  baseline: indexed(30, (index) =>
    result({
      rule: "DUPLICATE001",
      message: `Collision defect ${pad(index)}`,
      uri: `src/collision-${pad(index)}.cs`,
      line: 70 + index,
      snippet: `collision_anchor_${pad(index)}();`,
      fingerprint: "shared-collision",
    })),
  candidate: indexed(30, (index) =>
    result({
      rule: "DUPLICATE001",
      message: `Collision defect ${pad(index)}`,
      uri: `src/collision-${pad(index)}.cs`,
      line: 70 + index,
      snippet: `collision_anchor_${pad(index)}();`,
      fingerprint: "shared-collision",
    })),
  caseLabels: labels({
    pairs: indexed(30, (index) => pair(index, "unchanged")),
  }),
  notes: `
# Duplicate producer fingerprints

All thirty findings share one producer fingerprint value in the same run/rule
bucket. That evidence must be degraded; distinct paths and snippets provide the
only safe one-to-one identities.
`,
});

writeCase({
  name: "message-modifications",
  baseline: indexed(25, (index) =>
    result({
      message: `Original explanation ${pad(index)}`,
      uri: `src/modified-${pad(index)}.cs`,
      line: 80 + index,
      snippet: `modified_anchor_${pad(index)}();`,
      fingerprint: `modified-${pad(index)}`,
    })),
  candidate: indexed(25, (index) =>
    result({
      message: `Rewritten explanation ${pad(index)}`,
      uri: `src/modified-${pad(index)}.cs`,
      line: 80 + index,
      snippet: `modified_anchor_${pad(index)}();`,
      fingerprint: `modified-${pad(index)}`,
    })),
  caseLabels: labels({
    pairs: indexed(25, (index) => pair(index, "modified")),
  }),
  notes: `
# Message-only modifications

Unique producer fingerprints preserve continuity while every human-facing
message changes materially. Classification must be modified, not unchanged.
`,
});

writeCase({
  name: "two-findings-one-line",
  baseline: indexed(15, (index) =>
    result({
      rule: "SAME-LINE001",
      message: `Distinct same-line defect ${pad(index)}`,
      uri: "src/crowded.cs",
      line: 100,
      snippet: `sink_${pad(index)}(input);`,
      fingerprint: `same-line-${pad(index)}`,
    })),
  candidate: indexed(15, (index) =>
    result({
      rule: "SAME-LINE001",
      message: `Distinct same-line defect ${pad(index)}`,
      uri: "src/crowded.cs",
      line: 100,
      snippet: `sink_${pad(index)}(input);`,
      fingerprint: `same-line-${pad(index)}`,
    })),
  caseLabels: labels({
    pairs: indexed(15, (index) => pair(index, "unchanged")),
  }),
  notes: `
# Two-or-more findings on one line

Fifteen findings share one rule, file, and source line. Distinct messages,
snippets, and producer fingerprints prevent location-only coalescing.
`,
});

const ambiguousBaseline = [
  result({
    rule: "ONE-TO-MANY",
    message: "One baseline rival",
    uri: "src/one-to-many.cs",
    line: 10,
    snippet: "same_anchor();",
  }),
  result({
    rule: "MANY-TO-ONE",
    message: "First baseline rival",
    uri: "src/many-to-one.cs",
    line: 20,
    snippet: "same_other_anchor();",
  }),
  result({
    rule: "MANY-TO-ONE",
    message: "First baseline rival",
    uri: "src/many-to-one.cs",
    line: 20,
    snippet: "same_other_anchor();",
  }),
];
const ambiguousCandidate = [
  result({
    rule: "ONE-TO-MANY",
    message: "One baseline rival",
    uri: "src/one-to-many.cs",
    line: 10,
    snippet: "same_anchor();",
  }),
  result({
    rule: "ONE-TO-MANY",
    message: "One baseline rival",
    uri: "src/one-to-many.cs",
    line: 10,
    snippet: "same_anchor();",
  }),
  result({
    rule: "MANY-TO-ONE",
    message: "First baseline rival",
    uri: "src/many-to-one.cs",
    line: 20,
    snippet: "same_other_anchor();",
  }),
];
writeCase({
  name: "assignment-ambiguity",
  baseline: ambiguousBaseline,
  candidate: ambiguousCandidate,
  caseLabels: labels({
    expectedAmbiguous: [
      ...indexed(3, (index) => findingKey("baseline", index)),
      ...indexed(3, (index) => findingKey("candidate", index)),
    ],
  }),
  notes: `
# One-to-many and many-to-one ambiguity

Two disconnected components present equal semantic assignments: one baseline
has two indistinguishable candidates, and two indistinguishable baselines have
one candidate. Every involved identity must be refused as ambiguous.
`,
});

writeCase({
  name: "new-and-resolved",
  baseline: indexed(12, (index) =>
    result({
      rule: `RESOLVED-${pad(index)}`,
      message: `Resolved defect ${pad(index)}`,
      uri: `src/resolved-${pad(index)}.cs`,
      line: 110 + index,
      snippet: `resolved_${pad(index)}();`,
    })),
  candidate: indexed(12, (index) =>
    result({
      rule: `NEW-${pad(index)}`,
      message: `New defect ${pad(index)}`,
      uri: `src/new-${pad(index)}.cs`,
      line: 120 + index,
      snippet: `new_${pad(index)}();`,
    })),
  caseLabels: labels({
    expectedResolved: indexed(
      12,
      (index) => findingKey("baseline", index)),
    expectedNew: indexed(
      12,
      (index) => findingKey("candidate", index)),
  }),
  notes: `
# New and resolved findings

Twelve baseline-only rule buckets and twelve candidate-only rule buckets prove
that unmatched identities are checked as complete labelled sets.
`,
});

writeCase({
  name: "malformed-json",
  baseline: [],
  candidate: [],
  rawBaseline: "{ this is not valid JSON }\n",
  caseLabels: labels({
    expectedInvalidInputs: ["baseline"],
    expectedDiagnostics: [
      {
        input: "baseline",
        code: "PARSE0100",
        severity: "error",
        stage: "parse",
        message: "The SARIF input is not valid JSON.",
        jsonPointer: "",
      },
    ],
    expectedExplanations: [],
  }),
  notes: `
# Malformed SARIF

The baseline is deliberately invalid JSON. Rejection is ground truth and is
evaluated deterministically without attempting to match partial findings.
`,
});
