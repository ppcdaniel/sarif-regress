#!/usr/bin/env python3
"""Create a bounded, promotable attestation for matcher-v3.2 bootstrap output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


MAXIMUM_BYTES = 64 * 1024 * 1024
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
COORDINATOR_JOB_NAME = "Compare Linux and Windows normalized bytes"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--linux-root", required=True)
    parser.add_argument("--windows-root", required=True)
    parser.add_argument("--verified-root", required=True)
    return parser.parse_args()


def read_bounded(path: Path) -> bytes:
    status = path.lstat()
    if not stat.S_ISREG(status.st_mode):
        raise SystemExit(f"Attestation input is not a regular file: {path}")
    if status.st_size <= 0 or status.st_size > MAXIMUM_BYTES:
        raise SystemExit(
            f"Attestation input {path.name!r} has invalid size {status.st_size}.")
    with path.open("rb") as stream:
        payload = stream.read(MAXIMUM_BYTES + 1)
    if len(payload) != status.st_size:
        raise SystemExit(f"Attestation input changed while reading: {path}")
    return payload


def sha256(path: Path) -> str:
    return hashlib.sha256(read_bounded(path)).hexdigest()


def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON property {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, object]:
    value = json.loads(read_bounded(path), object_pairs_hook=reject_duplicate)
    if not isinstance(value, dict):
        raise SystemExit(f"Attestation input is not a JSON object: {path.name}")
    return value


def required_decimal(name: str, maximum: int = 9_007_199_254_740_991) -> int:
    value = os.environ.get(name, "")
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise SystemExit(f"{name} is not a positive decimal integer.")
    parsed = int(value)
    if parsed > maximum:
        raise SystemExit(f"{name} exceeds its permitted range.")
    return parsed


def required_sha256(name: str) -> str:
    value = os.environ.get(name, "")
    if SHA256_PATTERN.fullmatch(value) is None or set(value) == {"0"}:
        raise SystemExit(f"{name} is not a nonzero lowercase SHA-256.")
    return value


def required_commit(name: str) -> str:
    value = os.environ.get(name, "")
    if COMMIT_PATTERN.fullmatch(value) is None or set(value) == {"0"}:
        raise SystemExit(f"{name} is not a nonzero lowercase commit SHA.")
    return value


def parse_checksum_manifest(path: Path) -> dict[str, str]:
    text = read_bounded(path).decode("utf-8", errors="strict")
    if not text.endswith("\n") or "\r" in text:
        raise SystemExit(f"{path.name} is not canonical LF text.")
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)", line)
        if match is None or match.group(2) in result:
            raise SystemExit(f"{path.name} contains an invalid entry.")
        result[match.group(2)] = match.group(1)
    return result


def require_identical(
    name: str, linux_root: Path, windows_root: Path, verified_root: Path
) -> str:
    linux = linux_root / name
    windows = windows_root / name
    verified = verified_root / name
    linux_payload = read_bounded(linux)
    windows_payload = read_bounded(windows)
    verified_payload = read_bounded(verified)
    if linux_payload != windows_payload or linux_payload != verified_payload:
        raise SystemExit(f"{name} is not byte-identical across candidate roots.")
    return hashlib.sha256(verified_payload).hexdigest()


def write_canonical(path: Path, value: dict[str, object]) -> None:
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def main() -> int:
    arguments = parse_arguments()
    repository = Path(arguments.repository_root).resolve(strict=True)
    linux_root = Path(arguments.linux_root).resolve(strict=True)
    windows_root = Path(arguments.windows_root).resolve(strict=True)
    verified_root = Path(arguments.verified_root).resolve(strict=True)
    for name, candidate_root in (
        ("Linux", linux_root),
        ("Windows", windows_root),
        ("verified", verified_root),
    ):
        if not candidate_root.is_relative_to(repository):
            raise SystemExit(f"{name} bootstrap root escapes the repository checkout.")
    workflow_head = required_commit("CHECKED_OUT_SOURCE_SHA")

    linux_artifact_id = required_decimal("LINUX_ARTIFACT_ID")
    windows_artifact_id = required_decimal("WINDOWS_ARTIFACT_ID")
    if linux_artifact_id == windows_artifact_id:
        raise SystemExit("Linux and Windows evidence reused one artifact ID.")
    linux_artifact_digest = required_sha256("LINUX_ARTIFACT_DIGEST")
    windows_artifact_digest = required_sha256("WINDOWS_ARTIFACT_DIGEST")

    exact_head_name = workflow_head
    linux_artifact_name = f"holdout-v3.2-candidate-linux-{exact_head_name}"
    windows_artifact_name = f"holdout-v3.2-candidate-windows-{exact_head_name}"

    identity_names = (
        "checksums.sha256",
        "comparison-summary.json",
        "development-corpus-report.json",
        "evaluation-metadata.json",
        "sarif-multitool-baseline.json",
        "sarif-regress-holdout.json",
        "v3.1-to-v3.2-delta.json",
    )
    identity_hashes = {
        name: require_identical(name, linux_root, windows_root, verified_root)
        for name in identity_names
    }

    manifest_path = repository / "validation" / "holdout" / "manifest.json"
    manifest_sha256 = sha256(manifest_path)
    metadata_path = verified_root / "evaluation-metadata.json"
    metadata = load_json(metadata_path)
    metadata_sha256 = identity_hashes["evaluation-metadata.json"]
    if metadata.get("repositoryCommitSha") != workflow_head:
        raise SystemExit("Bootstrap metadata is not bound to the workflow head.")
    if metadata.get("holdoutManifestSha256") != manifest_sha256:
        raise SystemExit("Bootstrap metadata does not hash the holdout manifest.")
    if metadata.get("matcherAlgorithmVersion") != "sarifregress/matcher/v3.2":
        raise SystemExit("Bootstrap metadata does not identify matcher-v3.2.")

    report_names = (
        "sarif-regress-holdout.json",
        "sarif-multitool-baseline.json",
        "v3.1-to-v3.2-delta.json",
    )
    sarif_report = load_json(verified_root / report_names[0])
    multitool_report = load_json(verified_root / report_names[1])
    delta_report = load_json(verified_root / report_names[2])
    if sarif_report.get("schemaVersion") != "3" or sarif_report.get(
        "reportKind"
    ) != "sarif-regress-exposed-holdout-regression":
        raise SystemExit("The matcher-v3.2 report repeats an obsolete holdout claim.")
    if delta_report.get("schemaVersion") != "1" or delta_report.get(
        "reportKind"
    ) != "matcher-v3.1-to-v3.2-delta":
        raise SystemExit("The matcher-v3.1-to-v3.2 delta has the wrong envelope.")
    for name, report in (
        (report_names[0], sarif_report),
        (report_names[1], multitool_report),
    ):
        evaluation = report.get("evaluation")
        if not isinstance(evaluation, dict):
            raise SystemExit(f"{name} has no evaluation identity.")
        if evaluation.get("repositoryCommitSha") != workflow_head:
            raise SystemExit(f"{name} is not bound to the workflow head.")
        if evaluation.get("holdoutManifestSha256") != manifest_sha256:
            raise SystemExit(f"{name} is not bound to the holdout manifest.")

    history_root = repository / "validation" / "history" / "matcher-v3.1"
    history_manifest_sha256 = sha256(history_root / "checksums.sha256")
    matcher_v31_report_sha256 = sha256(history_root / "sarif-regress-holdout.json")
    expected_delta_hashes = {
        "matcherV31HistoryChecksumManifestSha256": history_manifest_sha256,
        "matcherV31ReportSha256": matcher_v31_report_sha256,
        "matcherV32ReportSha256": identity_hashes[report_names[0]],
        "holdoutManifestSha256": manifest_sha256,
    }
    if delta_report.get("inputHashes") != expected_delta_hashes:
        raise SystemExit("The v3.1-to-v3.2 delta does not bind its exact inputs.")

    checksums = parse_checksum_manifest(verified_root / "checksums.sha256")
    required_checksums = {
        "validation/holdout/manifest.json": manifest_sha256,
        "validation/holdout/evaluation-metadata.json": metadata_sha256,
        "validation/expected/sarif-regress-holdout.json":
            identity_hashes[report_names[0]],
        "validation/expected/sarif-multitool-baseline.json":
            identity_hashes[report_names[1]],
        "validation/expected/v3.1-to-v3.2-delta.json":
            identity_hashes[report_names[2]],
        "validation/history/matcher-v3.1/checksums.sha256":
            history_manifest_sha256,
        "validation/history/matcher-v3.1/sarif-regress-holdout.json":
            matcher_v31_report_sha256,
    }
    for name, expected in required_checksums.items():
        if checksums.get(name) != expected:
            raise SystemExit(f"checksums.sha256 does not bind {name!r}.")

    comparison = load_json(verified_root / "comparison-summary.json")
    if comparison.get("schemaVersion") != "4" or comparison.get(
        "reportKind"
    ) != "holdout-external-baseline-comparison":
        raise SystemExit("comparison-summary.json has the wrong matcher-v3.2 envelope.")
    expected_comparison_hashes = {
        "holdoutManifestSha256": manifest_sha256,
        "evaluationMetadataSha256": metadata_sha256,
        "sarifRegressReportSha256": identity_hashes[report_names[0]],
        "sarifMultitoolBaselineReportSha256": identity_hashes[report_names[1]],
        "matcherV31ReportSha256": matcher_v31_report_sha256,
        "v31ToV32DeltaReportSha256": identity_hashes[report_names[2]],
    }
    if comparison.get("reportHashes") != expected_comparison_hashes:
        raise SystemExit("comparison-summary.json does not bind the bootstrap inputs.")
    conditions = comparison.get("releaseConditions")
    if not isinstance(conditions, dict):
        raise SystemExit("comparison-summary.json has no release conditions.")
    required_true_conditions = (
        "zeroIncorrectAmbiguityMatches",
        "noUnexplainedIngestionFailures",
        "noStructuralFailures",
        "evaluationCompleted",
        "everyChangedDecisionExplained",
    )
    if any(conditions.get(name) is not True for name in required_true_conditions):
        raise SystemExit("The bootstrap failed a safety condition unrelated to attestation.")
    if conditions.get("crossPlatformByteIdentity") is not False:
        raise SystemExit("The unbound bootstrap comparison is not fail-closed.")

    report_digests = {
        "sarifRegressHoldoutSha256": identity_hashes[report_names[0]],
        "sarifMultitoolBaselineSha256": identity_hashes[report_names[1]],
        "v31ToV32DeltaSha256": identity_hashes[report_names[2]],
    }
    run_id = required_decimal("GITHUB_RUN_ID")
    run_attempt = required_decimal("GITHUB_RUN_ATTEMPT", maximum=1000)
    attestation: dict[str, object] = {
        "schemaVersion": "4",
        "repository": "ppcdaniel/sarif-regress",
        "repositoryCommitSha": workflow_head,
        "holdoutManifestSha256": manifest_sha256,
        "evaluationMetadataSha256": metadata_sha256,
        "baseReports": report_digests,
        "githubActions": {
            "workflowPath": ".github/workflows/holdout-validation.yml",
            "runId": run_id,
            "runAttempt": run_attempt,
            "runUrl": (
                "https://github.com/ppcdaniel/sarif-regress/actions/runs/"
                f"{run_id}"
            ),
            "workflowHeadSha": workflow_head,
            # The coordinator succeeds before a separate refusal job intentionally
            # fails this unbound workflow. Keep both facts explicit and truthful.
            "workflowConclusion": "failure",
            "coordinatorJobConclusion": "success",
            "coordinatorJobName": COORDINATOR_JOB_NAME,
        },
        "artifacts": {
            "linux": {
                "name": linux_artifact_name,
                "artifactId": linux_artifact_id,
                "archiveSha256": linux_artifact_digest,
                "reportDigests": dict(report_digests),
            },
            "windows": {
                "name": windows_artifact_name,
                "artifactId": windows_artifact_id,
                "archiveSha256": windows_artifact_digest,
                "reportDigests": dict(report_digests),
            },
        },
        "byteIdentity": {
            "sarifRegressHoldout": True,
            "sarifMultitoolBaseline": True,
            "v31ToV32Delta": True,
        },
    }
    attestation_path = verified_root / "cross-platform-attestation.json"
    write_canonical(attestation_path, attestation)

    projection_name = "sparse-experiment-release-projection.json"
    _ = read_bounded(verified_root / projection_name)
    coordinator_names = tuple(
        sorted((*identity_names, attestation_path.name, projection_name))
    )
    coordinator_manifest = "".join(
        f"{sha256(verified_root / name)}  {name}\n" for name in coordinator_names
    )
    (verified_root / "cross-platform-checksums.sha256").write_text(
        coordinator_manifest, encoding="ascii", newline="\n")
    expected_output_names = set(coordinator_names) | {
        "cross-platform-checksums.sha256"
    }
    observed_output_names = {entry.name for entry in verified_root.iterdir()}
    if observed_output_names != expected_output_names:
        raise SystemExit("The verified bootstrap root contains an unexpected entry.")
    for name in expected_output_names:
        _ = read_bounded(verified_root / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
