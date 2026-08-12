#!/usr/bin/env python3
"""Authenticate exact-head holdout evidence before a tagged draft release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_ENTRIES = 64
MAX_REPOSITORY_MANIFEST_ENTRIES = 256
MAX_SAFE_INTEGER = 9_007_199_254_740_991
EXPECTED_MATCHER_VERSION = "sarifregress/matcher/v3.2"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REASON_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MANIFEST_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
REPOSITORY_MANIFEST_NAME_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
SEMVER_TAG_PATTERN = re.compile(
    r"^v(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)\."
    r"(0|[1-9][0-9]*)"
    r"(?:-(?P<prerelease>(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)

REQUIRED_EVIDENCE_FILES = frozenset(
    {
        "checksums.sha256",
        "comparison-summary.json",
        "cross-platform-attestation.json",
        "development-corpus-report.json",
        "sarif-multitool-baseline.json",
        "sarif-regress-holdout.json",
        "sparse-experiment-development-corpus-release-evidence.json",
        "sparse-experiment-gate-evidence.json",
        "sparse-experiment-observations.json",
        "sparse-experiment-release-composite-projection.json",
        "sparse-experiment-release-projection.json",
        "sparse-experiment-workflow-provenance.json",
        "v3.1-to-v3.2-delta.json",
    }
)
EVIDENCE_ROOT_FILES = REQUIRED_EVIDENCE_FILES | {
    "cross-platform-checksums.sha256",
}

RELEASE_CONDITIONS = (
    "precisionMet",
    "recallMet",
    "allProducerPrecisionMet",
    "allProducerRecallMet",
    "zeroIncorrectAmbiguityMatches",
    "noUnexplainedIngestionFailures",
    "noStructuralFailures",
    "completeLabelGraphSatisfied",
    "crossPlatformByteIdentity",
    "evaluationCompleted",
    "everyChangedDecisionExplained",
)
SAFETY_CONDITIONS = (
    "zeroIncorrectAmbiguityMatches",
    "noUnexplainedIngestionFailures",
    "noStructuralFailures",
    "crossPlatformByteIdentity",
    "evaluationCompleted",
    "everyChangedDecisionExplained",
)
STABLE_CONDITIONS = RELEASE_CONDITIONS
EXPECTED_THRESHOLDS = {
    "minimumPrecision": 0.95,
    "minimumRecall": 0.90,
    "minimumPerProducerPrecision": 0.95,
    "minimumPerProducerRecall": 0.80,
    "maximumIncorrectlyAutoMatchedAmbiguousCases": 0,
    "maximumUnexplainedIngestionFailures": 0,
    "maximumStructuralFailures": 0,
    "requireCompleteLabelGraph": True,
    "requireCrossPlatformByteIdentity": True,
    "requireCompletedEvaluation": True,
    "requireChangedDecisionExplanations": True,
}

ATTESTATION_KEYS = {
    "schemaVersion",
    "repository",
    "repositoryCommitSha",
    "holdoutManifestSha256",
    "evaluationMetadataSha256",
    "baseReports",
    "githubActions",
    "artifacts",
    "byteIdentity",
}
ACTION_KEYS = {
    "workflowPath",
    "runId",
    "runAttempt",
    "runUrl",
    "workflowHeadSha",
    "workflowConclusion",
    "coordinatorJobConclusion",
    "coordinatorJobName",
}
REPORT_DIGEST_KEYS = {
    "sarifRegressHoldoutSha256",
    "sarifMultitoolBaselineSha256",
    "v31ToV32DeltaSha256",
}
ARTIFACT_KEYS = {"name", "artifactId", "archiveSha256", "reportDigests"}
BYTE_IDENTITY_KEYS = {
    "sarifRegressHoldout",
    "sarifMultitoolBaseline",
    "v31ToV32Delta",
}
COMPARISON_HASH_KEYS = {
    "holdoutManifestSha256",
    "evaluationMetadataSha256",
    "sarifRegressReportSha256",
    "sarifMultitoolBaselineReportSha256",
    "matcherV31ReportSha256",
    "v31ToV32DeltaReportSha256",
}
DELTA_INPUT_HASH_KEYS = {
    "matcherV31HistoryChecksumManifestSha256",
    "matcherV31ReportSha256",
    "matcherV32ReportSha256",
    "holdoutManifestSha256",
}


class GateError(RuntimeError):
    """Raised when release evidence or policy is not safe to promote."""


def _require_real_directory(path: Path, area: str) -> Path:
    """Return an absolute directory path while rejecting a symlinked root."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        status = absolute.lstat()
    except OSError as error:
        raise GateError(f"Cannot inspect {area} {absolute}: {error}") from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
        raise GateError(f"{area} must be a real, non-symlink directory: {absolute}")
    return absolute


def _child_beneath(root: Path, relative_name: str) -> Path:
    """Resolve a fixed relative child without following directory symlinks."""

    parts = relative_name.split("/")
    if (not parts or any(part in ("", ".", "..") for part in parts)
            or "\\" in relative_name):
        raise GateError(f"Unsafe repository-relative input name: {relative_name!r}")
    current = root
    for part in parts[:-1]:
        current /= part
        try:
            status = current.lstat()
        except OSError as error:
            raise GateError(f"Cannot inspect required directory {current}: {error}") from error
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise GateError(f"Required directory is not a real directory: {current}")
    return current / parts[-1]


def _validate_evidence_root(root: Path) -> None:
    """Reject extra, missing, nested, and linked artifact entries."""

    try:
        entries = list(os.scandir(root))
    except OSError as error:
        raise GateError(f"Cannot enumerate evidence root {root}: {error}") from error
    names = {entry.name for entry in entries}
    if len(names) != len(entries) or names != EVIDENCE_ROOT_FILES:
        missing = sorted(EVIDENCE_ROOT_FILES - names)
        extra = sorted(names - EVIDENCE_ROOT_FILES)
        raise GateError(f"Evidence root differs; missing={missing}, extra={extra}.")
    for entry in entries:
        try:
            is_regular = entry.is_file(follow_symlinks=False)
        except OSError as error:
            raise GateError(f"Cannot inspect evidence entry {entry.name!r}: {error}") from error
        if not is_regular:
            raise GateError(
                f"Evidence entry is not a regular non-symlink file: {entry.name!r}")


def _read_regular_file(path: Path) -> bytes:
    """Read a bounded regular file without following a final-component symlink."""

    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"Cannot inspect required file {path}: {error}") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise GateError(f"Required input is not a regular non-symlink file: {path}")
    if before.st_size > MAX_FILE_BYTES:
        raise GateError(f"Required input exceeds {MAX_FILE_BYTES} bytes: {path}")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise GateError(f"Cannot open required file {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise GateError(f"Opened input is not a regular file: {path}")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise GateError(f"Required input changed while it was opened: {path}")
        if opened.st_size > MAX_FILE_BYTES:
            raise GateError(f"Required input exceeds {MAX_FILE_BYTES} bytes: {path}")

        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > MAX_FILE_BYTES:
            raise GateError(f"Required input exceeds {MAX_FILE_BYTES} bytes: {path}")
        after = os.fstat(descriptor)
        opened_identity = (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if opened_identity != after_identity or len(payload) != opened.st_size:
            raise GateError(f"Required input changed while it was read: {path}")
        return payload
    finally:
        os.close(descriptor)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"Duplicate JSON key is prohibited: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise GateError(f"Non-finite JSON number is prohibited: {value}")


def _load_json(path: Path) -> dict[str, Any]:
    payload = _read_regular_file(path)
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateError(f"JSON input is not UTF-8: {path}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except GateError:
        raise
    except (RecursionError, TypeError, ValueError) as error:
        raise GateError(f"Invalid JSON input {path}: {error}") from error
    if not isinstance(value, dict):
        raise GateError(f"JSON input must contain an object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(_read_regular_file(path)).hexdigest()


def _parse_cross_platform_manifest(path: Path) -> dict[str, str]:
    payload = _read_regular_file(path)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise GateError("Cross-platform checksum manifest must be ASCII.") from error
    if not text.endswith("\n") or "\r" in text:
        raise GateError("Cross-platform checksum manifest must use terminal LF bytes.")

    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise GateError("Malformed cross-platform checksum manifest line.")
        digest, name = match.groups()
        if MANIFEST_NAME_PATTERN.fullmatch(name) is None:
            raise GateError(f"Unsafe checksum-manifest filename: {name!r}")
        if name in entries:
            raise GateError(f"Duplicate checksum-manifest filename: {name!r}")
        entries[name] = digest
        if len(entries) > MAX_MANIFEST_ENTRIES:
            raise GateError("Cross-platform checksum manifest has too many entries.")
    if set(entries) != REQUIRED_EVIDENCE_FILES:
        missing = sorted(REQUIRED_EVIDENCE_FILES - set(entries))
        extra = sorted(set(entries) - REQUIRED_EVIDENCE_FILES)
        raise GateError(
            f"Cross-platform evidence set differs; missing={missing}, extra={extra}.")
    if list(entries) != sorted(entries):
        raise GateError("Cross-platform checksum manifest must be name-sorted.")
    return entries


def _parse_repository_manifest(path: Path) -> dict[str, str]:
    payload = _read_regular_file(path)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise GateError("Repository checksum manifest must be ASCII.") from error
    if not text.endswith("\n") or "\r" in text:
        raise GateError("Repository checksum manifest must use terminal LF bytes.")

    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise GateError("Malformed repository checksum manifest line.")
        digest, name = match.groups()
        if (REPOSITORY_MANIFEST_NAME_PATTERN.fullmatch(name) is None
                or any(part in ("", ".", "..") for part in name.split("/"))):
            raise GateError(f"Unsafe repository checksum filename: {name!r}")
        if name in entries:
            raise GateError(f"Duplicate repository checksum filename: {name!r}")
        entries[name] = digest
        if len(entries) > MAX_REPOSITORY_MANIFEST_ENTRIES:
            raise GateError("Repository checksum manifest has too many entries.")
    if list(entries) != sorted(entries):
        raise GateError("Repository checksum manifest must be name-sorted.")
    return entries


def _require_exact_keys(value: dict[str, Any], expected: set[str], area: str) -> None:
    if set(value) != expected:
        raise GateError(
            f"{area} keys differ; expected={sorted(expected)}, actual={sorted(value)}.")


def _require_positive_integer(value: Any, area: str, maximum: int) -> int:
    if (not isinstance(value, int) or isinstance(value, bool)
            or value <= 0 or value > maximum):
        raise GateError(f"{area} must be a positive bounded integer.")
    return value


def _require_sha256(value: Any, area: str) -> str:
    if (not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None
            or set(value) == {"0"}):
        raise GateError(f"{area} must be a lowercase SHA-256 digest.")
    return value


def _validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    _require_exact_keys(
        policy,
        {"$schema", "schemaVersion", "policyKind", "criteriaDocument", "channels"},
        "release policy",
    )
    expected_scalars = {
        "$schema": "schemas/release-gate-policy.schema.json",
        "schemaVersion": "1",
        "policyKind": "release-channel-readiness",
        "criteriaDocument": "docs/release-readiness.md#preview-and-stable-criteria",
    }
    for key, expected in expected_scalars.items():
        if policy.get(key) != expected:
            raise GateError(f"Release policy {key!r} is not {expected!r}.")

    channels = policy.get("channels")
    if not isinstance(channels, dict):
        raise GateError("Release policy channels must be an object.")
    _require_exact_keys(channels, {"preview", "stable"}, "release policy channels")
    for name in ("preview", "stable"):
        channel = channels[name]
        if not isinstance(channel, dict):
            raise GateError(f"Release policy channel {name!r} must be an object.")
        _require_exact_keys(channel, {"recommendation", "reasonIds"}, name)
        recommendation = channel.get("recommendation")
        if recommendation not in ("blocked", "ready"):
            raise GateError(f"Invalid {name} release recommendation.")
        reasons = channel.get("reasonIds")
        if not isinstance(reasons, list) or len(reasons) > 32:
            raise GateError(f"Invalid {name} release reason list.")
        if any(not isinstance(reason, str) or REASON_PATTERN.fullmatch(reason) is None
               for reason in reasons):
            raise GateError(f"Invalid {name} release reason identifier.")
        if reasons != sorted(set(reasons)):
            raise GateError(f"{name} release reasons must be unique and sorted.")
        if (recommendation == "ready") != (len(reasons) == 0):
            raise GateError(
                f"{name} recommendation must be ready exactly when reasonIds is empty.")
    return channels


def verify_release_gate(
    repository_root: Path,
    evidence_root: Path,
    source_sha: str,
    tag: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> str:
    """Verify evidence and return the selected channel when promotion is safe."""

    if COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise GateError("Source SHA must be one lowercase 40-character commit SHA.")
    tag_match = SEMVER_TAG_PATTERN.fullmatch(tag)
    if tag_match is None:
        raise GateError("Release tag must be a canonical v-prefixed Semantic Version.")
    channel_name = "preview" if tag_match.group("prerelease") else "stable"
    workflow_run_id = _require_positive_integer(
        workflow_run_id, "Workflow run ID", MAX_SAFE_INTEGER)
    workflow_run_attempt = _require_positive_integer(
        workflow_run_attempt, "Workflow run attempt", 1000)

    repository_root = _require_real_directory(repository_root, "Repository root")
    evidence_root = _require_real_directory(evidence_root, "Evidence root")
    _validate_evidence_root(evidence_root)

    manifest = _parse_cross_platform_manifest(
        evidence_root / "cross-platform-checksums.sha256")
    for name, expected_digest in manifest.items():
        actual_digest = _sha256(evidence_root / name)
        if actual_digest != expected_digest:
            raise GateError(f"Cross-platform checksum mismatch for {name!r}.")

    repository_inputs = {
        "holdoutManifestSha256": _sha256(_child_beneath(
            repository_root, "validation/holdout/manifest.json")),
        "evaluationMetadataSha256": _sha256(_child_beneath(
            repository_root, "validation/holdout/evaluation-metadata.json")),
        "matcherV31HistoryChecksumManifestSha256": _sha256(_child_beneath(
            repository_root, "validation/history/matcher-v3.1/checksums.sha256")),
        "matcherV31ReportSha256": _sha256(_child_beneath(
            repository_root,
            "validation/history/matcher-v3.1/sarif-regress-holdout.json")),
    }

    attestation = _load_json(evidence_root / "cross-platform-attestation.json")
    _require_exact_keys(attestation, ATTESTATION_KEYS, "cross-platform attestation")
    if attestation.get("schemaVersion") != "4":
        raise GateError("Cross-platform attestation has an unexpected schema version.")
    if attestation.get("repository") != "ppcdaniel/sarif-regress":
        raise GateError("Cross-platform attestation names an unexpected repository.")
    frozen_commit = attestation.get("repositoryCommitSha")
    if not isinstance(frozen_commit, str) or COMMIT_PATTERN.fullmatch(frozen_commit) is None:
        raise GateError("Cross-platform attestation has an invalid frozen commit SHA.")
    for key in ("holdoutManifestSha256", "evaluationMetadataSha256"):
        if attestation.get(key) != repository_inputs[key]:
            raise GateError(f"Cross-platform attestation does not bind current {key}.")

    metadata = _load_json(_child_beneath(
        repository_root, "validation/holdout/evaluation-metadata.json"))
    if metadata.get("repositoryCommitSha") != frozen_commit:
        raise GateError("Evaluation metadata and attestation frozen commits differ.")
    if metadata.get("holdoutManifestSha256") != repository_inputs[
            "holdoutManifestSha256"]:
        raise GateError("Evaluation metadata does not bind the current holdout manifest.")

    actions = attestation.get("githubActions")
    if not isinstance(actions, dict):
        raise GateError("Cross-platform attestation lacks githubActions.")
    _require_exact_keys(actions, ACTION_KEYS, "githubActions attestation")
    if actions.get("workflowPath") != ".github/workflows/holdout-validation.yml":
        raise GateError("Cross-platform attestation names an unexpected workflow.")
    if actions.get("runId") != workflow_run_id:
        raise GateError("Holdout evidence does not bind the current workflow run ID.")
    if actions.get("runAttempt") != workflow_run_attempt:
        raise GateError("Holdout evidence does not bind the current workflow run attempt.")
    expected_run_url = (
        "https://github.com/ppcdaniel/sarif-regress/actions/runs/"
        f"{workflow_run_id}")
    if actions.get("runUrl") != expected_run_url:
        raise GateError("Holdout evidence has an unexpected workflow run URL.")
    if actions.get("workflowHeadSha") != source_sha:
        raise GateError("Holdout evidence does not bind the exact tagged commit.")
    if actions.get("workflowConclusion") != "success":
        raise GateError("The holdout workflow did not attest a successful conclusion.")
    if actions.get("coordinatorJobConclusion") != "success":
        raise GateError("The holdout coordinator did not attest a successful conclusion.")
    if actions.get("coordinatorJobName") != (
            "Compare Linux and Windows normalized bytes"):
        raise GateError("Holdout evidence names an unexpected coordinator job.")

    byte_identity = attestation.get("byteIdentity")
    if not isinstance(byte_identity, dict):
        raise GateError("Holdout evidence lacks byte identity.")
    _require_exact_keys(byte_identity, BYTE_IDENTITY_KEYS, "byte identity")
    if any(value is not True for value in byte_identity.values()):
        raise GateError("Holdout evidence does not attest complete byte identity.")

    base_reports = attestation.get("baseReports")
    if not isinstance(base_reports, dict):
        raise GateError("Cross-platform attestation lacks base reports.")
    _require_exact_keys(base_reports, REPORT_DIGEST_KEYS, "base report digests")
    expected_base_reports = {
        "sarifRegressHoldoutSha256": _sha256(
            evidence_root / "sarif-regress-holdout.json"),
        "sarifMultitoolBaselineSha256": _sha256(
            evidence_root / "sarif-multitool-baseline.json"),
        "v31ToV32DeltaSha256": _sha256(
            evidence_root / "v3.1-to-v3.2-delta.json"),
    }
    if base_reports != expected_base_reports:
        raise GateError("Cross-platform attestation does not bind the downloaded reports.")

    artifacts = attestation.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"linux", "windows"}:
        raise GateError("Cross-platform attestation lacks both producer artifacts.")
    artifact_ids: list[int] = []
    for platform_name, artifact_name in (
        ("linux", "holdout-linux"),
        ("windows", "holdout-windows"),
    ):
        artifact = artifacts.get(platform_name)
        if not isinstance(artifact, dict):
            raise GateError(f"Invalid {platform_name} producer artifact attestation.")
        _require_exact_keys(artifact, ARTIFACT_KEYS, f"{platform_name} artifact")
        if artifact.get("name") != artifact_name:
            raise GateError(f"Invalid {platform_name} producer artifact attestation.")
        artifact_id = _require_positive_integer(
            artifact.get("artifactId"),
            f"{platform_name} producer artifact ID",
            MAX_SAFE_INTEGER,
        )
        artifact_ids.append(artifact_id)
        _require_sha256(
            artifact.get("archiveSha256"),
            f"{platform_name} producer artifact digest",
        )
        if artifact.get("reportDigests") != expected_base_reports:
            raise GateError(f"{platform_name} producer artifact report digests differ.")
    if artifact_ids[0] == artifact_ids[1]:
        raise GateError("Linux and Windows producer artifacts must have distinct IDs.")

    sarif_regress_report = _load_json(
        evidence_root / "sarif-regress-holdout.json")
    if sarif_regress_report.get("schemaVersion") != "3":
        raise GateError("SarifRegress holdout evidence has an unexpected schema version.")
    if sarif_regress_report.get("reportKind") != (
            "sarif-regress-exposed-holdout-regression"):
        raise GateError("SarifRegress holdout evidence repeats an obsolete claim.")

    for report_name, report in (
        ("sarif-regress-holdout.json", sarif_regress_report),
        (
            "sarif-multitool-baseline.json",
            _load_json(evidence_root / "sarif-multitool-baseline.json"),
        ),
    ):
        evaluation = report.get("evaluation")
        if not isinstance(evaluation, dict):
            raise GateError(f"{report_name} lacks evaluation metadata.")
        if evaluation.get("repositoryCommitSha") != frozen_commit:
            raise GateError(f"{report_name} identifies an unexpected frozen commit.")
        if evaluation.get("holdoutManifestSha256") != repository_inputs[
                "holdoutManifestSha256"]:
            raise GateError(f"{report_name} does not bind the current holdout manifest.")
        if evaluation.get("matcherAlgorithmVersion") != EXPECTED_MATCHER_VERSION:
            raise GateError(f"{report_name} identifies an unexpected matcher version.")

    delta = _load_json(evidence_root / "v3.1-to-v3.2-delta.json")
    if delta.get("schemaVersion") != "1":
        raise GateError("Matcher delta has an unexpected schema version.")
    if delta.get("reportKind") != "matcher-v3.1-to-v3.2-delta":
        raise GateError("Matcher delta has an unexpected report kind.")
    delta_hashes = delta.get("inputHashes")
    if not isinstance(delta_hashes, dict):
        raise GateError("Matcher delta lacks input hashes.")
    _require_exact_keys(delta_hashes, DELTA_INPUT_HASH_KEYS, "matcher delta input hashes")
    expected_delta_hashes = {
        "matcherV31HistoryChecksumManifestSha256": repository_inputs[
            "matcherV31HistoryChecksumManifestSha256"],
        "matcherV31ReportSha256": repository_inputs["matcherV31ReportSha256"],
        "matcherV32ReportSha256": expected_base_reports[
            "sarifRegressHoldoutSha256"],
        "holdoutManifestSha256": repository_inputs["holdoutManifestSha256"],
    }
    if delta_hashes != expected_delta_hashes:
        raise GateError("Matcher delta does not bind the current exact inputs.")

    repository_manifest = _parse_repository_manifest(
        evidence_root / "checksums.sha256")
    expected_repository_manifest_entries = {
        "validation/holdout/manifest.json": repository_inputs[
            "holdoutManifestSha256"],
        "validation/holdout/evaluation-metadata.json": repository_inputs[
            "evaluationMetadataSha256"],
        "validation/expected/sarif-regress-holdout.json": expected_base_reports[
            "sarifRegressHoldoutSha256"],
        "validation/expected/sarif-multitool-baseline.json": expected_base_reports[
            "sarifMultitoolBaselineSha256"],
        "validation/expected/v3.1-to-v3.2-delta.json": expected_base_reports[
            "v31ToV32DeltaSha256"],
        "validation/history/matcher-v3.1/checksums.sha256": repository_inputs[
            "matcherV31HistoryChecksumManifestSha256"],
        "validation/history/matcher-v3.1/sarif-regress-holdout.json": repository_inputs[
            "matcherV31ReportSha256"],
    }
    for name, expected_digest in expected_repository_manifest_entries.items():
        if repository_manifest.get(name) != expected_digest:
            raise GateError(f"Repository checksum manifest does not bind {name!r}.")

    comparison = _load_json(evidence_root / "comparison-summary.json")
    if comparison.get("schemaVersion") != "4":
        raise GateError("Comparison summary has an unexpected schema version.")
    if comparison.get("reportKind") != "holdout-external-baseline-comparison":
        raise GateError("Comparison summary has an unexpected report kind.")
    comparison_evaluation = comparison.get("evaluation")
    if not isinstance(comparison_evaluation, dict):
        raise GateError("Comparison summary lacks evaluation metadata.")
    if comparison_evaluation.get("repositoryCommitSha") != frozen_commit:
        raise GateError("Comparison summary identifies an unexpected frozen commit.")
    if comparison_evaluation.get("holdoutManifestSha256") != repository_inputs[
            "holdoutManifestSha256"]:
        raise GateError("Comparison summary does not bind the current holdout manifest.")
    if comparison_evaluation.get(
            "matcherAlgorithmVersion") != EXPECTED_MATCHER_VERSION:
        raise GateError("Comparison summary identifies an unexpected matcher version.")
    report_hashes = comparison.get("reportHashes")
    if not isinstance(report_hashes, dict):
        raise GateError("Comparison summary lacks reportHashes.")
    _require_exact_keys(report_hashes, COMPARISON_HASH_KEYS, "comparison report hashes")
    expected_comparison_hashes = {
        "sarifRegressReportSha256": expected_base_reports[
            "sarifRegressHoldoutSha256"],
        "sarifMultitoolBaselineReportSha256": expected_base_reports[
            "sarifMultitoolBaselineSha256"],
        "v31ToV32DeltaReportSha256": expected_base_reports[
            "v31ToV32DeltaSha256"],
        "holdoutManifestSha256": attestation.get("holdoutManifestSha256"),
        "evaluationMetadataSha256": attestation.get("evaluationMetadataSha256"),
        "matcherV31ReportSha256": repository_inputs["matcherV31ReportSha256"],
    }
    if report_hashes != expected_comparison_hashes:
        raise GateError("Comparison summary does not bind all exact report inputs.")

    thresholds = comparison.get("thresholds")
    if not isinstance(thresholds, dict):
        raise GateError("Comparison summary lacks fixed release thresholds.")
    _require_exact_keys(thresholds, set(EXPECTED_THRESHOLDS), "release thresholds")
    for name, expected_value in EXPECTED_THRESHOLDS.items():
        actual_value = thresholds.get(name)
        if type(actual_value) is not type(expected_value) or actual_value != expected_value:
            raise GateError(f"Release threshold {name!r} differs from the fixed gate.")

    conditions = comparison.get("releaseConditions")
    if not isinstance(conditions, dict):
        raise GateError("Comparison summary lacks releaseConditions.")
    _require_exact_keys(conditions, set(RELEASE_CONDITIONS), "release conditions")
    if any(not isinstance(value, bool) for value in conditions.values()):
        raise GateError("Comparison release conditions must all be Boolean.")
    failed_safety = [name for name in SAFETY_CONDITIONS if conditions.get(name) is not True]
    if failed_safety:
        raise GateError(f"Holdout safety conditions failed: {failed_safety}.")

    recommendation = comparison.get("releaseRecommendation")
    if recommendation not in ("blocked", "ready"):
        raise GateError("Comparison summary has an invalid release recommendation.")

    development = _load_json(evidence_root / "development-corpus-report.json")
    if development.get("passed") is not True or development.get("failures") != []:
        raise GateError("Development corpus is not green.")

    channels = _validate_policy(
        _load_json(_child_beneath(
            repository_root, "validation/release-gate-policy.json")))
    selected = channels[channel_name]
    if selected["recommendation"] != "ready":
        raise GateError(
            f"{channel_name} release is blocked: {', '.join(selected['reasonIds'])}.")
    if channel_name == "stable":
        failed_stable = [
            name for name in STABLE_CONDITIONS if conditions.get(name) is not True
        ]
        if failed_stable:
            raise GateError(f"Stable holdout conditions failed: {failed_stable}.")
        if recommendation != "ready":
            raise GateError("Stable release is blocked by the holdout recommendation.")
    return channel_name


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    return parser.parse_args()


def main() -> int:
    options = _parse_args()
    try:
        channel = verify_release_gate(
            options.repository_root,
            options.evidence_root,
            options.source_sha,
            options.tag,
            options.workflow_run_id,
            options.workflow_run_attempt,
        )
    except (GateError, OSError) as error:
        print(f"Release gate failed: {error}", file=sys.stderr)
        return 1
    print(f"Authenticated exact-head holdout evidence permits the {channel} channel.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
