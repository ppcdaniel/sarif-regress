#!/usr/bin/env python3
"""Select the fail-closed matcher-v3.2 evidence promotion stage."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat


MAXIMUM_BYTES = 4 * 1024 * 1024
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
MATCHER_VERSION = "sarifregress/matcher/v3.2"
COORDINATOR_JOB_NAME = "Compare Linux and Windows normalized bytes"


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate JSON property {name!r}")
        result[name] = value
    return result


def load_json(root: Path, relative_name: str) -> dict[str, object]:
    path = root / relative_name
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode):
        raise SystemExit(f"Evidence-stage input is not a regular file: {relative_name}.")
    if status.st_size <= 0 or status.st_size > MAXIMUM_BYTES:
        raise SystemExit(f"Evidence-stage input has invalid size: {relative_name}.")
    with path.open("rb") as stream:
        payload = stream.read(MAXIMUM_BYTES + 1)
    if len(payload) != status.st_size:
        raise SystemExit(f"Evidence-stage input changed while reading: {relative_name}.")
    value = json.loads(payload, object_pairs_hook=reject_duplicates)
    if not isinstance(value, dict):
        raise SystemExit(f"Evidence-stage input is not a JSON object: {relative_name}.")
    return value


def require_actions_and_artifacts(
    attestation: dict[str, object],
) -> tuple[dict[str, object], dict[str, object], str]:
    if attestation.get("schemaVersion") != "4":
        raise SystemExit("The committed matcher-v3.2 attestation is not schema version 4.")
    actions = attestation.get("githubActions")
    artifacts = attestation.get("artifacts")
    if not isinstance(actions, dict) or not isinstance(artifacts, dict):
        raise SystemExit("The committed matcher-v3.2 attestation is incomplete.")
    workflow_head = actions.get("workflowHeadSha")
    if not isinstance(workflow_head, str) or COMMIT_PATTERN.fullmatch(
        workflow_head
    ) is None:
        raise SystemExit("The committed matcher-v3.2 attestation has no exact workflow head.")
    if actions.get("coordinatorJobName") != COORDINATOR_JOB_NAME:
        raise SystemExit("The committed matcher-v3.2 attestation names the wrong coordinator.")
    if actions.get("coordinatorJobConclusion") != "success":
        raise SystemExit("The committed matcher-v3.2 coordinator did not succeed.")
    return actions, artifacts, workflow_head


def artifact_names(artifacts: dict[str, object]) -> tuple[object, object]:
    linux = artifacts.get("linux")
    windows = artifacts.get("windows")
    if not isinstance(linux, dict) or not isinstance(windows, dict):
        raise SystemExit("The committed matcher-v3.2 attestation lacks producer artifacts.")
    return linux.get("name"), windows.get("name")


def detect_stage(root: Path) -> str:
    erratum = load_json(root, "validation/holdout/interpretation-erratum.json")
    binding = erratum.get("currentReportBinding")
    if not isinstance(binding, dict) or binding.get(
        "matcherAlgorithmVersion"
    ) != MATCHER_VERSION:
        raise SystemExit("Erratum does not identify matcher-v3.2.")
    status = binding.get("status")
    if status == "candidate-unbound":
        return "stage1"
    if status != "bound":
        raise SystemExit("Erratum has an unknown matcher-v3.2 binding state.")

    comparison = load_json(root, "validation/expected/comparison-summary.json")
    if comparison.get("schemaVersion") != "4" or comparison.get(
        "reportKind"
    ) != "holdout-external-baseline-comparison":
        raise SystemExit("The bound matcher-v3.2 comparison has the wrong envelope.")
    evaluation = comparison.get("evaluation")
    conditions = comparison.get("releaseConditions")
    if (
        not isinstance(evaluation, dict)
        or evaluation.get("matcherAlgorithmVersion") != MATCHER_VERSION
        or not isinstance(conditions, dict)
    ):
        raise SystemExit("The bound matcher-v3.2 comparison identity is incomplete.")
    byte_identity = conditions.get("crossPlatformByteIdentity")
    if not isinstance(byte_identity, bool):
        raise SystemExit("The bound matcher-v3.2 comparison lacks byte-identity state.")

    attestation = load_json(root, "validation/holdout/cross-platform-attestation.json")
    actions, artifacts, workflow_head = require_actions_and_artifacts(attestation)
    linux_name, windows_name = artifact_names(artifacts)
    candidate_names = (
        f"holdout-v3.2-candidate-linux-{workflow_head}",
        f"holdout-v3.2-candidate-windows-{workflow_head}",
    )
    normal_names = ("holdout-linux", "holdout-windows")
    observed_names = (linux_name, windows_name)
    if observed_names == candidate_names:
        if actions.get("workflowConclusion") != "failure":
            raise SystemExit("A bootstrap attestation must record its failed workflow.")
    elif observed_names == normal_names:
        if actions.get("workflowConclusion") != "success":
            raise SystemExit("A normal attestation must record its successful workflow.")
    else:
        raise SystemExit("The committed matcher-v3.2 artifact names are inconsistent.")

    if not byte_identity:
        if observed_names != candidate_names:
            raise SystemExit(
                "Stage 2 requires the exact committed stage-1 candidate attestation."
            )
        return "stage2"
    return "normal"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    arguments = parser.parse_args()
    root = arguments.repository_root.resolve(strict=True)
    print(detect_stage(root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
