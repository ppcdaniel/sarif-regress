#!/usr/bin/env python3
"""Verify authentic sparse PMD capture, projection, and label topology."""

from __future__ import annotations

import argparse
import os
import platform
import re
import stat
import sys
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Final, Iterable, Mapping, Sequence

from project_pmd_sarif import (
    ALGORITHM_VERSION,
    ProjectionError,
    _canonical_absolute_path,
    _open_anchored_directory,
    assert_portable_deterministic_sarif,
    build_audit,
    project_document,
    read_strict_json,
    sha256_bytes,
    stable_json_bytes,
)


PMD_VERSION: Final = "7.26.0"
PMD_SOURCE_COMMIT: Final = "8fd38edf285a33e1164f66205ebe243441db9557"
PMD_PROJECT_URL: Final = "https://github.com/pmd/pmd"
PMD_RELEASE_URL: Final = (
    "https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.26.0"
)
PMD_LICENSE: Final = "LicenseRef-PMD-BSD-Style"
PMD_ARCHIVE_NAME: Final = "pmd-dist-7.26.0-bin.zip"
PMD_ARCHIVE_URL: Final = (
    "https://github.com/pmd/pmd/releases/download/pmd_releases/7.26.0/"
    "pmd-dist-7.26.0-bin.zip"
)
PMD_ARCHIVE_BYTES: Final = 73_646_044
PMD_ARCHIVE_SHA256: Final = (
    "9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
)
PMD_HELP_SHA256: Final = (
    "babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91"
)
PMD_ARCHIVE_PREFIX: Final = "pmd-bin-7.26.0"
PYTHON_VERSION: Final = "3.12.13"
JAVA_DISTRIBUTION: Final = "Eclipse Temurin"
JAVA_VENDOR: Final = "Eclipse Adoptium"
JAVA_VERSION: Final = "17.0.19+10"
RUNNER_LABEL: Final = "ubuntu-24.04"
RUNNER_IMAGE_OS: Final = "ubuntu24"
RUNNER_IMAGE_VERSION_PATTERN: Final = re.compile(r"^[0-9]{8}\.[0-9]+\.[0-9]+$")
CAPTURE_CONTRACT_VERSION: Final = "pmd-authentic-sparse-capture/v1"
FILE_SIZE_LIMIT_BLOCK_BYTES: Final = 1024
DOWNLOAD_FILE_SIZE_BLOCKS: Final = (
    PMD_ARCHIVE_BYTES + FILE_SIZE_LIMIT_BLOCK_BYTES - 1
) // FILE_SIZE_LIMIT_BLOCK_BYTES
MAX_ARTIFACT_FILES: Final = 128
MAX_ARTIFACT_BYTES: Final = 128 * 1024 * 1024
MAX_SOURCE_BYTES: Final = 1024 * 1024
MAX_PROMOTED_FILE_BYTES: Final = 16 * 1024 * 1024
PROMOTED_SIDE_FIELDS: Final = frozenset(
    {
        "sourceRoot",
        "sarifPath",
        "projectionAuditPath",
        "sourceTreeSha256",
        "rawCaptureSha256",
        "rawCaptureBytes",
        "projectedSarifSha256",
        "projectedSarifBytes",
        "projectionAuditSha256",
        "resultCount",
    }
)
PROMOTED_FAMILY_FIELDS: Final = frozenset(
    {"id", "labelsPath", "rulesetPath", "baseline", "candidate"}
)
SIDES: Final = ("baseline", "candidate")
MARKER_PATTERN: Final = re.compile(
    r"(?i)(?:\bHOLDOUT\b|\bGROUND[-_ ]?TRUTH\b|"
    r"\bIDENTITY[-_:](?:ID|KEY|MARKER)\b)"
)
STABLE_ID_PATTERN: Final = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
SOURCE_CALL_PATTERN: Final = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*\.printStackTrace\(\);"
)
CAPTURE_COMMAND: Final = (
    "pmd",
    "check",
    "--dir",
    ".",
    "--format",
    "sarif",
    "--no-cache",
    "--no-fail-on-violation",
    "--no-progress",
    "--relativize-paths-with",
    "<side-source-root>",
    "--report-file",
    "<raw-capture>",
    "--rulesets",
    "<family-ruleset>",
    "--threads",
    "0",
    "--use-version",
    "java-17",
)
DOWNLOAD_COMMAND: Final = (
    "curl",
    "--disable",
    "--fail",
    "--location",
    "--max-filesize",
    "<archive-bytes>",
    "--proto",
    "=https",
    "--retry",
    "3",
    "--retry-all-errors",
    "--show-error",
    "--silent",
    "--tlsv1.2",
    "--output",
    "<archive-destination>",
    "<archive-url>",
)

Selector = tuple[str, str, int, int, int, int, str]


class VerificationError(RuntimeError):
    """Raised when capture evidence violates the research contract."""


def capture_contract() -> dict[str, object]:
    """Return the canonical producer, runtime, and command capture contract."""

    return {
        "schemaVersion": "1",
        "contractVersion": CAPTURE_CONTRACT_VERSION,
        "producer": {
            "name": "PMD",
            "version": PMD_VERSION,
            "sourceCommit": PMD_SOURCE_COMMIT,
            "projectUrl": PMD_PROJECT_URL,
            "releaseUrl": PMD_RELEASE_URL,
            "license": PMD_LICENSE,
            "archiveName": PMD_ARCHIVE_NAME,
            "archiveUrl": PMD_ARCHIVE_URL,
            "archiveBytes": PMD_ARCHIVE_BYTES,
            "archiveSha256": PMD_ARCHIVE_SHA256,
            "archivePrefix": PMD_ARCHIVE_PREFIX,
            "helpSha256": PMD_HELP_SHA256,
        },
        "runtime": {
            "pythonVersion": PYTHON_VERSION,
            "javaDistribution": JAVA_DISTRIBUTION,
            "javaVendor": JAVA_VENDOR,
            "javaVersion": JAVA_VERSION,
        },
        "runner": {
            "label": RUNNER_LABEL,
            "imageOS": RUNNER_IMAGE_OS,
            "operatingSystem": "Linux",
            "architecture": "x86_64",
        },
        "projectionAlgorithmVersion": ALGORITHM_VERSION,
        "captureCommand": list(CAPTURE_COMMAND),
        "download": {
            "command": list(DOWNLOAD_COMMAND),
            "fileSizeLimitBlocks": DOWNLOAD_FILE_SIZE_BLOCKS,
            "fileSizeLimitBlockBytes": FILE_SIZE_LIMIT_BLOCK_BYTES,
        },
    }


def capture_contract_sha256() -> str:
    """Hash the canonical contract using its stable JSON representation."""

    return sha256_bytes(stable_json_bytes(capture_contract(), sort_keys=True))


def verify_capture_contract(observed: object) -> str:
    """Reject any shell-side producer, runtime, or command contract drift."""

    if observed != capture_contract():
        raise VerificationError("Shell capture contract differs from the canonical contract.")
    return capture_contract_sha256()


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise VerificationError(f"{context} must be an object.")
    return value


def _require_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise VerificationError(f"{context} must be an array.")
    return value


def _safe_relative(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise VerificationError(f"{context} must be a portable relative path.")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise VerificationError(f"{context} must be a safe relative path.")
    return path.as_posix()


def _require_real_directory(path: Path, context: str) -> Path:
    """Preserve path identity while rejecting linked path components."""

    try:
        canonical = _canonical_absolute_path(path, context)
        descriptor = _open_anchored_directory(canonical)
    except ProjectionError as error:
        raise VerificationError(f"{context} must be a real canonical directory.") from error
    os.close(descriptor)
    return canonical


def _canonical_command_path(value: str, context: str) -> str:
    try:
        return os.fspath(_canonical_absolute_path(Path(value), context))
    except ProjectionError as error:
        raise VerificationError(f"{context} must be a canonical absolute path.") from error


def expected_capture_command(
    executable: str,
    source_root: str,
    raw_capture: str,
    ruleset: str,
) -> tuple[str, ...]:
    """Materialize the one allowed PMD argv from canonical placeholders."""

    replacements = {
        "pmd": _canonical_command_path(executable, "PMD executable"),
        "<side-source-root>": _canonical_command_path(source_root, "side source root"),
        "<raw-capture>": _canonical_command_path(raw_capture, "raw capture"),
        "<family-ruleset>": _canonical_command_path(ruleset, "family ruleset"),
    }
    return tuple(replacements.get(argument, argument) for argument in CAPTURE_COMMAND)


def verify_capture_command(
    arguments: Sequence[str],
    executable: str,
    source_root: str,
    raw_capture: str,
    ruleset: str,
) -> None:
    """Prove that the exact argv about to execute is the attested PMD command."""

    expected = expected_capture_command(executable, source_root, raw_capture, ruleset)
    if tuple(arguments) != expected:
        raise VerificationError("Runtime PMD argv differs from the canonical capture command.")


def expected_download_command(destination: str) -> tuple[str, ...]:
    """Materialize the one allowed bounded archive download argv."""

    replacements = {
        "<archive-bytes>": str(PMD_ARCHIVE_BYTES),
        "<archive-destination>": _canonical_command_path(
            destination,
            "archive destination",
        ),
        "<archive-url>": PMD_ARCHIVE_URL,
    }
    return tuple(replacements.get(argument, argument) for argument in DOWNLOAD_COMMAND)


def verify_download_command(
    arguments: Sequence[str],
    destination: str,
    file_size_limit_blocks: int,
) -> None:
    """Bind curl's transfer ceiling and inherited file limit to the contract."""

    if file_size_limit_blocks != DOWNLOAD_FILE_SIZE_BLOCKS:
        raise VerificationError("Download file-size limit differs from the contract.")
    if tuple(arguments) != expected_download_command(destination):
        raise VerificationError("Runtime curl argv differs from the bounded download command.")


def _read_regular_beneath(
    root: Path,
    relative: PurePosixPath,
    context: str,
    maximum_bytes: int = MAX_SOURCE_BYTES,
) -> bytes:
    """Read one bounded regular file through a fixed no-follow root handle."""

    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise VerificationError(f"{context} is not a safe relative path.")
    try:
        root_descriptor = _open_anchored_directory(root)
    except ProjectionError as error:
        raise VerificationError(f"{context} has an unsafe root.") from error
    descriptor = os.dup(root_descriptor)
    os.close(root_descriptor)
    try:
        for index, part in enumerate(relative.parts):
            final = index == len(relative.parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not final:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_size > maximum_bytes:
            raise VerificationError(
                f"{context} must be a regular file no larger than {maximum_bytes} bytes."
            )
        chunks: list[bytes] = []
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, maximum_bytes + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
            if observed > maximum_bytes:
                raise VerificationError(
                    f"{context} exceeds its {maximum_bytes}-byte limit."
                )
        return b"".join(chunks)
    except OSError as error:
        raise VerificationError(f"{context} is missing, linked, or inaccessible.") from error
    finally:
        os.close(descriptor)


def _selector(value: object, context: str) -> Selector:
    item = _require_mapping(value, context)
    region = _require_mapping(item.get("region"), f"{context}.region")
    rule_id = item.get("ruleId")
    artifact_uri = item.get("artifactUri")
    message = item.get("message")
    if not all(isinstance(field, str) and field for field in (rule_id, artifact_uri, message)):
        raise VerificationError(f"{context} has an incomplete textual selector.")
    artifact = _safe_relative(artifact_uri, f"{context}.artifactUri")
    position_names = ("startLine", "startColumn", "endLine", "endColumn")
    positions = tuple(region.get(name) for name in position_names)
    if any(
        not isinstance(position, int)
        or isinstance(position, bool)
        or position < 1
        for position in positions
    ):
        raise VerificationError(f"{context} has an invalid region.")
    start_line, start_column, end_line, end_column = positions
    if (end_line, end_column) < (start_line, start_column):
        raise VerificationError(f"{context} region ends before it starts.")
    return (
        rule_id,
        artifact,
        start_line,
        start_column,
        end_line,
        end_column,
        message,
    )


def _result_selector(value: object, context: str) -> Selector:
    result = _require_mapping(value, context)
    rule_id = result.get("ruleId")
    message = _require_mapping(result.get("message"), f"{context}.message").get("text")
    locations = _require_list(result.get("locations"), f"{context}.locations")
    if not locations:
        raise VerificationError(f"{context} has no primary location.")
    location = _require_mapping(locations[0], f"{context}.locations[0]")
    physical = _require_mapping(
        location.get("physicalLocation"),
        f"{context}.locations[0].physicalLocation",
    )
    artifact = _require_mapping(
        physical.get("artifactLocation"),
        f"{context}.artifactLocation",
    ).get("uri")
    region = _require_mapping(physical.get("region"), f"{context}.region")
    return _selector(
        {
            "ruleId": rule_id,
            "artifactUri": artifact,
            "region": region,
            "message": message,
        },
        context,
    )


def _walk(value: object) -> Iterable[tuple[str | None, object]]:
    stack: list[tuple[str | None, object]] = [(None, value)]
    while stack:
        key, current = stack.pop()
        yield key, current
        if isinstance(current, dict):
            stack.extend((child_key, child) for child_key, child in current.items())
        elif isinstance(current, list):
            stack.extend((key, child) for child in current)


def _flatten_results(document: object, context: str) -> list[object]:
    root = _require_mapping(document, context)
    if root.get("version") != "2.1.0":
        raise VerificationError(f"{context} is not SARIF 2.1.0.")
    runs = _require_list(root.get("runs"), f"{context}.runs")
    if len(runs) != 1:
        raise VerificationError(f"{context} must contain exactly one PMD run.")
    results: list[object] = []
    for run_index, value in enumerate(runs):
        run = _require_mapping(value, f"{context}.runs[{run_index}]")
        driver = _require_mapping(
            _require_mapping(run.get("tool"), f"{context}.runs[{run_index}].tool").get("driver"),
            f"{context}.runs[{run_index}].tool.driver",
        )
        if driver.get("name") != "PMD" or driver.get("version") != PMD_VERSION:
            raise VerificationError(f"{context} is not authentic PMD {PMD_VERSION} output.")
        invocations = _require_list(
            run.get("invocations"),
            f"{context}.runs[{run_index}].invocations",
        )
        if len(invocations) != 1:
            raise VerificationError(
                f"{context}.runs[{run_index}] must contain exactly one PMD invocation."
            )
        invocation = _require_mapping(
            invocations[0],
            f"{context}.runs[{run_index}].invocations[0]",
        )
        if invocation.get("executionSuccessful") is not True:
            raise VerificationError(
                f"{context}.runs[{run_index}] PMD invocation did not succeed."
            )
        for notification_kind in (
            "toolConfigurationNotifications",
            "toolExecutionNotifications",
        ):
            notifications = _require_list(
                invocation.get(notification_kind),
                f"{context}.runs[{run_index}].invocations[0].{notification_kind}",
            )
            if notifications:
                raise VerificationError(
                    f"{context} PMD invocation contains {notification_kind}."
                )
        results.extend(_require_list(run.get("results"), f"{context}.runs[{run_index}].results"))
    if not results:
        raise VerificationError(f"{context} contains no PMD results.")
    return results


def _verify_sparse_and_uncontaminated(
    results: Sequence[object],
    label_ids: set[str],
    context: str,
) -> None:
    folded_ids = {value.casefold() for value in label_ids}
    for result_index, result in enumerate(results):
        for key, value in _walk(result):
            if key in {"fingerprints", "partialFingerprints"}:
                raise VerificationError(
                    f"{context} result {result_index} contains producer fingerprints."
                )
            if key == "snippet":
                raise VerificationError(
                    f"{context} result {result_index} contains an embedded snippet."
                )
            if isinstance(value, str):
                folded = value.casefold()
                if MARKER_PATTERN.search(value) or any(token in folded for token in folded_ids):
                    raise VerificationError(
                        f"{context} result {result_index} contains ground-truth text."
                    )


def _verify_selector_source(case_root: Path, side: str, selector: Selector) -> None:
    artifact = PurePosixPath(selector[1])
    source_root = case_root / side / "source"
    try:
        payload = _read_regular_beneath(
            source_root,
            artifact,
            f"{side} selector source {artifact}",
        )
    except VerificationError as error:
        raise VerificationError(
            f"Label selector does not resolve inside {side} source: {artifact}."
        ) from error
    try:
        lines = payload.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as error:
        raise VerificationError(f"Cannot read selector source: {artifact}.") from error
    start_line, start_column, end_line, end_column = selector[2:6]
    if start_line != end_line or start_line > len(lines):
        raise VerificationError(f"Selector region is outside source: {artifact}.")
    line = lines[start_line - 1]
    if end_column > len(line) or start_column > end_column:
        raise VerificationError(f"Selector columns are outside source: {artifact}.")
    selected = line[start_column - 1 : end_column]
    if SOURCE_CALL_PATTERN.fullmatch(selected) is None:
        raise VerificationError(
            f"Selector does not identify the complete PMD call in source: {artifact}."
        )


def _verify_source_exhaustiveness(
    case_root: Path,
    side: str,
    result_selectors: Sequence[Selector],
) -> None:
    source_root = case_root / side / "source"
    observed: list[tuple[str, int, int, int, int]] = []
    for path in sorted(source_root.rglob("*.java")):
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"Source tree contains an unsafe Java entry: {path}.")
        relative = path.relative_to(source_root).as_posix()
        payload = _read_regular_beneath(
            source_root,
            PurePosixPath(relative),
            f"{case_root.name}/{side} source {relative}",
        )
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise VerificationError(
                f"Source tree contains non-UTF-8 Java: {relative}."
            ) from error
        for line_number, line in enumerate(text.splitlines(), start=1):
            for match in SOURCE_CALL_PATTERN.finditer(line):
                observed.append(
                    (
                        relative,
                        line_number,
                        match.start() + 1,
                        line_number,
                        match.end(),
                    )
                )
    projected = [(item[1], *item[2:6]) for item in result_selectors]
    if sorted(observed) != sorted(projected):
        raise VerificationError(
            f"{case_root.name}/{side} source calls and PMD regions are not exhaustive."
        )


def _strictly_monotonic(values: Sequence[int]) -> bool:
    return len(values) >= 2 and (
        all(left < right for left, right in zip(values, values[1:]))
        or all(left > right for left, right in zip(values, values[1:]))
    )


def _verify_proof_paths(case_root: Path, proof_value: object, context: str) -> None:
    proof = _require_mapping(proof_value, f"{context}.sourceTransformation")
    for side in ("baseline", "candidate"):
        path_key = f"{side}SourcePath"
        hash_key = f"{side}FileSha256"
        value = proof.get(path_key)
        if value is None:
            continue
        relative = _safe_relative(value, f"{context}.{path_key}")
        if not relative.startswith(f"{side}/source/"):
            raise VerificationError(f"{context}.{path_key} names the wrong source side.")
        try:
            payload = _read_regular_beneath(
                case_root,
                PurePosixPath(relative),
                f"{context}.{path_key}",
            )
        except VerificationError as error:
            raise VerificationError(f"{context}.{path_key} is not contained.") from error
        declared_hash = proof.get(hash_key)
        if declared_hash is not None:
            if not isinstance(declared_hash, str) or not SHA256_PATTERN.fullmatch(declared_hash):
                raise VerificationError(f"{context}.{hash_key} is invalid.")
            if sha256_bytes(payload) != declared_hash:
                raise VerificationError(f"{context}.{hash_key} does not match source.")


def verify_family_labels(
    case_root: Path,
    baseline_document: object,
    candidate_document: object,
) -> None:
    """Verify selectors form a unique exhaustive partition of both SARIF sides."""

    labels_path = case_root / "labels.json"
    labels_value, _ = read_strict_json(labels_path)
    labels = _require_mapping(labels_value, str(labels_path))
    family_id = labels.get("familyId")
    if family_id != case_root.name or labels.get("producerFamily") != "pmd":
        raise VerificationError(f"{labels_path} does not identify its family.")
    if (
        labels.get("baselineSarif") != "baseline.sarif"
        or labels.get("candidateSarif") != "candidate.sarif"
    ):
        raise VerificationError(f"{labels_path} does not name projected side SARIF.")

    categories = {
        name: _require_list(labels.get(name), f"{labels_path}:{name}")
        for name in ("relationships", "new", "resolved", "ambiguities")
    }
    label_ids: set[str] = set()
    for category, entries in categories.items():
        for index, value in enumerate(entries):
            entry = _require_mapping(value, f"{labels_path}:{category}[{index}]")
            label_id = entry.get("id")
            if (
                not isinstance(label_id, str)
                or STABLE_ID_PATTERN.fullmatch(label_id) is None
                or label_id in label_ids
            ):
                raise VerificationError(f"{labels_path} has an invalid or duplicate label ID.")
            label_ids.add(label_id)
            _verify_proof_paths(case_root, entry.get("sourceTransformation"), label_id)

    documents = {"baseline": baseline_document, "candidate": candidate_document}
    selectors_by_side: dict[str, list[Selector]] = {}
    positions_by_side: dict[str, dict[Selector, list[int]]] = {}
    for side, document in documents.items():
        results = _flatten_results(document, f"{family_id}/{side}")
        _verify_sparse_and_uncontaminated(results, label_ids, f"{family_id}/{side}")
        selectors = [
            _result_selector(result, f"{family_id}/{side}/results[{index}]")
            for index, result in enumerate(results)
        ]
        selectors_by_side[side] = selectors
        positions: dict[Selector, list[int]] = defaultdict(list)
        for index, selector in enumerate(selectors):
            positions[selector].append(index)
        positions_by_side[side] = positions
        _verify_source_exhaustiveness(case_root, side, selectors)

    used: dict[str, dict[int, str]] = {"baseline": {}, "candidate": {}}
    relationship_position_pairs: list[tuple[int, int]] = []

    def register_selector(side: str, selector: Selector, context: str) -> Selector:
        matches = positions_by_side[side].get(selector, [])
        if len(matches) != 1:
            raise VerificationError(
                f"{context} resolves to {len(matches)} {side} SARIF results; "
                "exactly one is required."
            )
        result_index = matches[0]
        previous = used[side].get(result_index)
        if previous is not None:
            raise VerificationError(
                f"{context} reuses {side} result {result_index}, already owned by {previous}."
            )
        used[side][result_index] = context
        _verify_selector_source(case_root, side, selector)
        return selector

    def register(side: str, value: object, context: str) -> Selector:
        return register_selector(side, _selector(value, context), context)

    for index, value in enumerate(categories["relationships"]):
        entry = _require_mapping(value, f"relationships[{index}]")
        label_id = str(entry["id"])
        baseline = register("baseline", entry.get("baseline"), f"{label_id}.baseline")
        candidate = register("candidate", entry.get("candidate"), f"{label_id}.candidate")
        relationship_position_pairs.append(
            (
                positions_by_side["baseline"][baseline][0],
                positions_by_side["candidate"][candidate][0],
            )
        )
        classification = entry.get("expectedClassification")
        if classification == "unchanged" and baseline != candidate:
            raise VerificationError(f"{label_id} is not structurally unchanged.")
        if classification == "moved":
            if (
                baseline[0] != candidate[0]
                or baseline[6] != candidate[6]
                or baseline[1:6] == candidate[1:6]
            ):
                raise VerificationError(f"{label_id} is not a message-stable location move.")
        elif classification not in {"unchanged", "modified"}:
            raise VerificationError(f"{label_id} has an unsupported relationship class.")

    for index, value in enumerate(categories["new"]):
        entry = _require_mapping(value, f"new[{index}]")
        if entry.get("expectedClassification") != "new":
            raise VerificationError("A candidate-only endpoint is not classified new.")
        register("candidate", entry.get("candidate"), f"{entry['id']}.candidate")

    for index, value in enumerate(categories["resolved"]):
        entry = _require_mapping(value, f"resolved[{index}]")
        if entry.get("expectedClassification") != "resolved":
            raise VerificationError("A baseline-only endpoint is not classified resolved.")
        register("baseline", entry.get("baseline"), f"{entry['id']}.baseline")

    for index, value in enumerate(categories["ambiguities"]):
        entry = _require_mapping(value, f"ambiguities[{index}]")
        label_id = str(entry["id"])
        baseline_values = _require_list(entry.get("baseline"), f"{label_id}.baseline")
        candidate_values = _require_list(entry.get("candidate"), f"{label_id}.candidate")
        if entry.get("expected") != "refuse":
            raise VerificationError(f"{label_id} does not require refusal.")
        shape = entry.get("shape")
        cardinality = (len(baseline_values), len(candidate_values))
        valid_shape = (
            (shape == "one-to-many" and cardinality[0] == 1 and cardinality[1] >= 2)
            or (shape == "many-to-one" and cardinality[0] >= 2 and cardinality[1] == 1)
            or (shape == "many-to-many" and cardinality[0] >= 2 and cardinality[1] >= 2)
        )
        if not valid_shape:
            raise VerificationError(f"{label_id} has invalid ambiguity cardinality {cardinality}.")
        for side, values in (("baseline", baseline_values), ("candidate", candidate_values)):
            selectors = [
                _selector(value, f"{label_id}.{side}[{member_index}]")
                for member_index, value in enumerate(values)
            ]
            if len(set(selectors)) != len(selectors):
                raise VerificationError(
                    f"{label_id}.{side} ambiguity set contains duplicate selectors."
                )
            for member_index, selector in enumerate(sorted(selectors)):
                register_selector(
                    side,
                    selector,
                    f"{label_id}.{side}[canonical:{member_index}]",
                )

    for side in ("baseline", "candidate"):
        expected = set(range(len(selectors_by_side[side])))
        if set(used[side]) != expected:
            missing = sorted(expected - set(used[side]))
            raise VerificationError(
                f"{family_id}/{side} labels are not exhaustive; first missing result "
                f"is {missing[0]}."
            )
    candidate_sequence = [
        candidate_position
        for _, candidate_position in sorted(relationship_position_pairs)
    ]
    if _strictly_monotonic(candidate_sequence):
        raise VerificationError(f"{family_id} relationship order exposes raw result ordering.")


def _verify_projection(
    *,
    raw_path: Path,
    projected_path: Path,
    audit_path: Path,
    source_root: Path,
    logical_source_root: str,
    family_id: str,
    side: str,
) -> object:
    raw_document, raw_payload = read_strict_json(raw_path)
    projected_document, projected_payload = read_strict_json(projected_path)
    audit_document, audit_payload = read_strict_json(audit_path)
    try:
        assert_portable_deterministic_sarif(projected_document, source_root)
        expected_document, changes, result_count = project_document(raw_document, source_root)
        expected_projected = stable_json_bytes(expected_document, sort_keys=False)
        expected_audit = build_audit(
            family_id=family_id,
            side=side,
            logical_source_root=logical_source_root,
            raw_payload=raw_payload,
            projected_payload=expected_projected,
            changes=changes,
            result_count=result_count,
            capture_contract_sha256=capture_contract_sha256(),
        )
    except ProjectionError as error:
        raise VerificationError(str(error)) from error
    if projected_payload != expected_projected or projected_document != expected_document:
        raise VerificationError(
            f"{family_id}/{side} projection changes data other than controlled URI prefixes."
        )
    expected_audit_payload = stable_json_bytes(expected_audit, sort_keys=True)
    if audit_document != expected_audit or audit_payload != expected_audit_payload:
        raise VerificationError(f"{family_id}/{side} projection audit is not reproducible.")
    return projected_document


def _enumerate_artifact_files(root: Path) -> dict[str, Path]:
    try:
        root_status = root.lstat()
    except OSError as error:
        raise VerificationError("Capture artifact root is missing.") from error
    if stat.S_ISLNK(root_status.st_mode) or not stat.S_ISDIR(root_status.st_mode):
        raise VerificationError("Capture artifact root must be a real directory.")
    files: dict[str, Path] = {}
    total = 0
    stack = [root]
    directories = 0
    while stack:
        directory = stack.pop()
        directories += 1
        if directories > MAX_ARTIFACT_FILES:
            raise VerificationError("Capture artifact contains too many directories.")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise VerificationError("Capture artifact directory cannot be read.") from error
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            status = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode):
                raise VerificationError(f"Capture artifact contains a link: {relative}.")
            if stat.S_ISDIR(status.st_mode):
                stack.append(path)
                continue
            if not stat.S_ISREG(status.st_mode):
                raise VerificationError(f"Capture artifact contains a special file: {relative}.")
            if len(files) >= MAX_ARTIFACT_FILES:
                raise VerificationError("Capture artifact contains too many files.")
            total += status.st_size
            if total > MAX_ARTIFACT_BYTES:
                raise VerificationError("Capture artifact exceeds its aggregate byte budget.")
            files[relative] = path
    return files


def _verify_checksums(capture_root: Path, files: Mapping[str, Path]) -> None:
    checksum_path = files.get("checksums.sha256")
    if checksum_path is None:
        raise VerificationError("Capture checksum manifest is missing.")
    payload = checksum_path.read_bytes()
    try:
        text = payload.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise VerificationError("Capture checksum manifest is not ASCII.") from error
    if not text.endswith("\n"):
        raise VerificationError("Capture checksum manifest must end with LF.")
    observed: dict[str, str] = {}
    order: list[str] = []
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)", line)
        if match is None or match.group(2) in observed:
            raise VerificationError("Capture checksum manifest has an invalid entry.")
        observed[match.group(2)] = match.group(1)
        order.append(match.group(2))
    if order != sorted(order):
        raise VerificationError("Capture checksums are not ordinal-sorted.")
    expected = set(files) - {"checksums.sha256"}
    if set(observed) != expected:
        raise VerificationError("Capture checksum coverage is not exhaustive.")
    for relative in sorted(expected):
        if sha256_bytes(files[relative].read_bytes()) != observed[relative]:
            raise VerificationError(f"Capture checksum mismatch: {relative}.")


def environment_evidence(
    source_sha: str,
    image_os: str,
    image_version: str,
    contract_sha256: str,
) -> dict[str, object]:
    """Build deterministic hosted-capture environment evidence."""

    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise VerificationError("Source SHA must be one full lowercase Git SHA-1.")
    if (
        image_os != RUNNER_IMAGE_OS
        or RUNNER_IMAGE_VERSION_PATTERN.fullmatch(image_version) is None
    ):
        raise VerificationError("Hosted runner image evidence is invalid.")
    if contract_sha256 != capture_contract_sha256():
        raise VerificationError("Capture contract SHA-256 is not canonical.")
    actual_python = platform.python_version()
    if actual_python != PYTHON_VERSION:
        raise VerificationError(f"Expected Python {PYTHON_VERSION}; found {actual_python}.")
    return {
        "schemaVersion": "1",
        "sourceSha": source_sha,
        "captureContract": {
            "version": CAPTURE_CONTRACT_VERSION,
            "sha256": contract_sha256,
        },
        "runner": {
            "label": RUNNER_LABEL,
            "imageOS": image_os,
            "imageVersion": image_version,
            "operatingSystem": "Linux",
            "architecture": "x86_64",
        },
        "runtime": {
            "pythonVersion": PYTHON_VERSION,
            "javaDistribution": JAVA_DISTRIBUTION,
            "javaVendor": JAVA_VENDOR,
            "javaVersion": JAVA_VERSION,
        },
        "producer": {
            "name": "PMD",
            "version": PMD_VERSION,
            "sourceCommit": PMD_SOURCE_COMMIT,
            "projectUrl": PMD_PROJECT_URL,
            "releaseUrl": PMD_RELEASE_URL,
            "license": PMD_LICENSE,
            "archiveName": PMD_ARCHIVE_NAME,
            "archiveUrl": PMD_ARCHIVE_URL,
            "archiveBytes": PMD_ARCHIVE_BYTES,
            "archiveSha256": PMD_ARCHIVE_SHA256,
            "archivePrefix": PMD_ARCHIVE_PREFIX,
            "helpSha256": PMD_HELP_SHA256,
        },
        "captureCommand": list(CAPTURE_COMMAND),
        "download": {
            "command": list(DOWNLOAD_COMMAND),
            "fileSizeLimitBlocks": DOWNLOAD_FILE_SIZE_BLOCKS,
            "fileSizeLimitBlockBytes": FILE_SIZE_LIMIT_BLOCK_BYTES,
        },
    }


def write_environment_evidence(
    output: Path,
    source_sha: str,
    image_os: str,
    image_version: str,
    contract_sha256: str,
) -> None:
    evidence = environment_evidence(
        source_sha,
        image_os,
        image_version,
        contract_sha256,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream:
        stream.write(stable_json_bytes(evidence, sort_keys=True))


def _verify_environment(
    path: Path,
    expected_source_sha: str,
    expected_image_os: str,
    expected_image_version: str,
) -> None:
    document, payload = read_strict_json(path)
    expected = environment_evidence(
        expected_source_sha,
        expected_image_os,
        expected_image_version,
        capture_contract_sha256(),
    )
    if document != expected or payload != stable_json_bytes(expected, sort_keys=True):
        raise VerificationError("Capture environment evidence is not canonical or complete.")


def verify_capture(
    research_root: Path,
    capture_root: Path,
    source_sha: str,
    expected_image_os: str,
    expected_image_version: str,
) -> None:
    """Verify the complete hosted PMD research capture artifact."""

    research_root = _require_real_directory(research_root, "research root")
    capture_root = _require_real_directory(capture_root, "capture root")
    files = _enumerate_artifact_files(capture_root)
    _verify_checksums(capture_root, files)
    environment_path = files.get("capture-environment.json")
    if environment_path is None:
        raise VerificationError("Capture environment evidence is missing.")
    _verify_environment(
        environment_path,
        source_sha,
        expected_image_os,
        expected_image_version,
    )

    cases_root = research_root / "cases"
    family_roots = sorted(
        path
        for path in cases_root.iterdir()
        if path.is_dir() and not path.is_symlink()
    )
    if len(family_roots) < 2:
        raise VerificationError("At least two PMD research families are required.")
    captured_family_root = capture_root / "cases"
    captured_names = sorted(path.name for path in captured_family_root.iterdir() if path.is_dir())
    expected_names = [path.name for path in family_roots]
    if captured_names != expected_names:
        raise VerificationError("Captured family set differs from research inputs.")
    expected_files = {"capture-environment.json", "checksums.sha256"}
    for family_id in expected_names:
        for side in ("baseline", "candidate"):
            expected_files.update(
                {
                    f"cases/{family_id}/{side}.raw.sarif",
                    f"cases/{family_id}/{side}.sarif",
                    f"cases/{family_id}/{side}.projection-audit.json",
                }
            )
    if set(files) != expected_files:
        raise VerificationError("Capture artifact file set is not exact.")

    for case_root in family_roots:
        family_id = case_root.name
        if STABLE_ID_PATTERN.fullmatch(family_id) is None:
            raise VerificationError(f"Invalid family ID: {family_id}.")
        output_root = captured_family_root / family_id
        projected_documents: dict[str, object] = {}
        for side in ("baseline", "candidate"):
            source_root = case_root / side / "source"
            logical_source_root = f"cases/{family_id}/{side}/source"
            projected_documents[side] = _verify_projection(
                raw_path=output_root / f"{side}.raw.sarif",
                projected_path=output_root / f"{side}.sarif",
                audit_path=output_root / f"{side}.projection-audit.json",
                source_root=source_root,
                logical_source_root=logical_source_root,
                family_id=family_id,
                side=side,
            )
        verify_family_labels(
            case_root,
            projected_documents["baseline"],
            projected_documents["candidate"],
        )


def _require_sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise VerificationError(f"{context} must be one lowercase SHA-256 digest.")
    return value


def _require_positive_integer(value: object, context: str, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 1
        or value > maximum
    ):
        raise VerificationError(
            f"{context} must be an integer from 1 through {maximum}."
        )
    return value


def _require_exact_path(value: object, expected: str, context: str) -> None:
    observed = _safe_relative(value, context)
    if observed != expected:
        raise VerificationError(f"{context} must be {expected!r}.")


def _promotion_family_names(research_root: Path) -> list[str]:
    cases_root = _require_real_directory(research_root / "cases", "research cases root")
    names: list[str] = []
    try:
        entries = sorted(os.scandir(cases_root), key=lambda entry: entry.name)
    except OSError as error:
        raise VerificationError("Research cases root cannot be read.") from error
    for entry in entries:
        try:
            status = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise VerificationError(f"Cannot inspect research case {entry.name}.") from error
        if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
            raise VerificationError(
                f"Research cases root contains a non-directory entry: {entry.name}."
            )
        if STABLE_ID_PATTERN.fullmatch(entry.name) is None:
            raise VerificationError(f"Invalid family ID: {entry.name}.")
        _require_real_directory(Path(entry.path), f"research family {entry.name}")
        names.append(entry.name)
    if len(names) < 2:
        raise VerificationError("At least two PMD research families are required.")
    return names


def _promotion_capture_files(family_names: Sequence[str]) -> set[str]:
    expected = {"capture-environment.json", "checksums.sha256"}
    for family_id in family_names:
        for side in SIDES:
            expected.update(
                {
                    f"cases/{family_id}/{side}.raw.sarif",
                    f"cases/{family_id}/{side}.sarif",
                    f"cases/{family_id}/{side}.projection-audit.json",
                }
            )
    return expected


def _read_promoted_file(research_root: Path, relative: str, context: str) -> bytes:
    return _read_regular_beneath(
        research_root,
        PurePosixPath(relative),
        context,
        MAX_PROMOTED_FILE_BYTES,
    )


def _verify_promoted_side(
    *,
    research_root: Path,
    capture_files: Mapping[str, Path],
    family_id: str,
    side: str,
    side_value: object,
    manifest_contract_sha256: str,
) -> None:
    context = f"manifest family {family_id}.{side}"
    manifest_side = _require_mapping(side_value, context)
    if set(manifest_side) != PROMOTED_SIDE_FIELDS:
        raise VerificationError(f"{context} fields do not match the promotion contract.")

    logical_source_root = f"cases/{family_id}/{side}/source"
    projected_relative = f"cases/{family_id}/{side}.sarif"
    audit_relative = f"capture-evidence/projection-audits/{family_id}/{side}.json"
    _require_exact_path(
        manifest_side.get("sourceRoot"),
        logical_source_root,
        f"{context}.sourceRoot",
    )
    _require_exact_path(
        manifest_side.get("sarifPath"),
        projected_relative,
        f"{context}.sarifPath",
    )
    _require_exact_path(
        manifest_side.get("projectionAuditPath"),
        audit_relative,
        f"{context}.projectionAuditPath",
    )
    _require_sha256(manifest_side.get("sourceTreeSha256"), f"{context}.sourceTreeSha256")

    raw_capture_relative = f"cases/{family_id}/{side}.raw.sarif"
    staged_projected_relative = f"cases/{family_id}/{side}.sarif"
    staged_audit_relative = f"cases/{family_id}/{side}.projection-audit.json"
    raw_payload = capture_files[raw_capture_relative].read_bytes()
    staged_projected_path = capture_files[staged_projected_relative]
    staged_audit_path = capture_files[staged_audit_relative]
    projected_document, staged_projected_payload = read_strict_json(staged_projected_path)
    audit_value, staged_audit_payload = read_strict_json(staged_audit_path)
    audit = _require_mapping(audit_value, f"{family_id}/{side} projection audit")

    committed_projected_payload = _read_promoted_file(
        research_root,
        projected_relative,
        f"committed {family_id}/{side} projected SARIF",
    )
    if committed_projected_payload != staged_projected_payload:
        raise VerificationError(
            f"{family_id}/{side} committed projected SARIF differs from the capture artifact."
        )
    committed_audit_payload = _read_promoted_file(
        research_root,
        audit_relative,
        f"committed {family_id}/{side} projection audit",
    )
    if committed_audit_payload != staged_audit_payload:
        raise VerificationError(
            f"{family_id}/{side} committed projection audit differs from the capture artifact."
        )

    raw_hash = sha256_bytes(raw_payload)
    raw_bytes = len(raw_payload)
    manifest_raw_hash = _require_sha256(
        manifest_side.get("rawCaptureSha256"),
        f"{context}.rawCaptureSha256",
    )
    manifest_raw_bytes = _require_positive_integer(
        manifest_side.get("rawCaptureBytes"),
        f"{context}.rawCaptureBytes",
        MAX_PROMOTED_FILE_BYTES,
    )
    audit_raw = _require_mapping(audit.get("rawSarif"), f"{family_id}/{side} audit.rawSarif")
    audit_raw_hash = _require_sha256(
        audit_raw.get("sha256"),
        f"{family_id}/{side} audit.rawSarif.sha256",
    )
    audit_raw_bytes = _require_positive_integer(
        audit_raw.get("bytes"),
        f"{family_id}/{side} audit.rawSarif.bytes",
        MAX_PROMOTED_FILE_BYTES,
    )
    if len({raw_hash, manifest_raw_hash, audit_raw_hash}) != 1:
        raise VerificationError(f"{family_id}/{side} raw capture SHA-256 is not cross-bound.")
    if len({raw_bytes, manifest_raw_bytes, audit_raw_bytes}) != 1:
        raise VerificationError(f"{family_id}/{side} raw capture byte size is not cross-bound.")

    projected_hash = sha256_bytes(staged_projected_payload)
    projected_bytes = len(staged_projected_payload)
    results = _flatten_results(projected_document, f"{family_id}/{side} promoted SARIF")
    result_count = len(results)
    manifest_projected_hash = _require_sha256(
        manifest_side.get("projectedSarifSha256"),
        f"{context}.projectedSarifSha256",
    )
    manifest_projected_bytes = _require_positive_integer(
        manifest_side.get("projectedSarifBytes"),
        f"{context}.projectedSarifBytes",
        MAX_PROMOTED_FILE_BYTES,
    )
    manifest_result_count = _require_positive_integer(
        manifest_side.get("resultCount"),
        f"{context}.resultCount",
        10_000,
    )
    audit_projected = _require_mapping(
        audit.get("projectedSarif"),
        f"{family_id}/{side} audit.projectedSarif",
    )
    audit_projected_hash = _require_sha256(
        audit_projected.get("sha256"),
        f"{family_id}/{side} audit.projectedSarif.sha256",
    )
    audit_projected_bytes = _require_positive_integer(
        audit_projected.get("bytes"),
        f"{family_id}/{side} audit.projectedSarif.bytes",
        MAX_PROMOTED_FILE_BYTES,
    )
    audit_result_count = _require_positive_integer(
        audit_projected.get("resultCount"),
        f"{family_id}/{side} audit.projectedSarif.resultCount",
        10_000,
    )
    if len({projected_hash, manifest_projected_hash, audit_projected_hash}) != 1:
        raise VerificationError(
            f"{family_id}/{side} projected SARIF SHA-256 is not cross-bound."
        )
    if len({projected_bytes, manifest_projected_bytes, audit_projected_bytes}) != 1:
        raise VerificationError(
            f"{family_id}/{side} projected SARIF byte size is not cross-bound."
        )
    if len({result_count, manifest_result_count, audit_result_count}) != 1:
        raise VerificationError(f"{family_id}/{side} result count is not cross-bound.")

    manifest_audit_hash = _require_sha256(
        manifest_side.get("projectionAuditSha256"),
        f"{context}.projectionAuditSha256",
    )
    if sha256_bytes(staged_audit_payload) != manifest_audit_hash:
        raise VerificationError(
            f"{family_id}/{side} projection audit SHA-256 is not cross-bound."
        )
    if (
        audit.get("schemaVersion") != "1"
        or audit.get("algorithmVersion") != ALGORITHM_VERSION
        or audit.get("familyId") != family_id
        or audit.get("side") != side
        or audit.get("logicalSourceRoot") != logical_source_root
        or audit.get("captureContractSha256") != manifest_contract_sha256
    ):
        raise VerificationError(
            f"{family_id}/{side} projection audit identity is not cross-bound."
        )


def verify_promotion(research_root: Path, capture_root: Path) -> None:
    """Bind a previously verified hosted capture to committed research evidence."""

    research_root = _require_real_directory(research_root, "research root")
    capture_root = _require_real_directory(capture_root, "capture root")
    family_names = _promotion_family_names(research_root)
    capture_files = _enumerate_artifact_files(capture_root)
    if set(capture_files) != _promotion_capture_files(family_names):
        raise VerificationError("Capture artifact file set is not exact for promotion.")
    _verify_checksums(capture_root, capture_files)

    manifest_relative = "manifest.json"
    manifest_payload = _read_promoted_file(
        research_root,
        manifest_relative,
        "research manifest",
    )
    manifest_value, parsed_manifest_payload = read_strict_json(
        research_root / manifest_relative
    )
    if manifest_payload != parsed_manifest_payload:
        raise VerificationError("Research manifest changed while it was being verified.")
    manifest = _require_mapping(manifest_value, "research manifest")
    producer = _require_mapping(manifest.get("producer"), "manifest.producer")
    capture = _require_mapping(producer.get("capture"), "manifest.producer.capture")
    contract = _require_mapping(
        capture.get("contract"),
        "manifest.producer.capture.contract",
    )
    manifest_contract_sha256 = _require_sha256(
        contract.get("sha256"),
        "manifest.producer.capture.contract.sha256",
    )
    if manifest_contract_sha256 != capture_contract_sha256():
        raise VerificationError("Manifest capture contract SHA-256 is not canonical.")

    environment_value, _ = read_strict_json(capture_files["capture-environment.json"])
    environment = _require_mapping(environment_value, "capture environment")
    environment_contract = _require_mapping(
        environment.get("captureContract"),
        "capture environment.captureContract",
    )
    if environment_contract.get("sha256") != manifest_contract_sha256:
        raise VerificationError(
            "Capture environment and manifest contract SHA-256 are not cross-bound."
        )

    families = _require_list(manifest.get("families"), "manifest.families")
    manifest_names: list[str] = []
    family_values: dict[str, dict[str, object]] = {}
    for index, family_value in enumerate(families):
        family = _require_mapping(family_value, f"manifest.families[{index}]")
        if set(family) != PROMOTED_FAMILY_FIELDS:
            raise VerificationError(
                f"manifest.families[{index}] fields do not match the promotion contract."
            )
        family_id = family.get("id")
        if (
            not isinstance(family_id, str)
            or STABLE_ID_PATTERN.fullmatch(family_id) is None
            or family_id in family_values
        ):
            raise VerificationError("Manifest has an invalid or duplicate family ID.")
        manifest_names.append(family_id)
        family_values[family_id] = family
    if manifest_names != family_names:
        raise VerificationError(
            "Manifest families must exactly and ordinally match research and capture families."
        )

    for family_id in family_names:
        family = family_values[family_id]
        _require_exact_path(
            family.get("labelsPath"),
            f"cases/{family_id}/labels.json",
            f"manifest family {family_id}.labelsPath",
        )
        _require_exact_path(
            family.get("rulesetPath"),
            f"cases/{family_id}/pmd-ruleset.xml",
            f"manifest family {family_id}.rulesetPath",
        )
        for side in SIDES:
            raw_committed = research_root / f"cases/{family_id}/{side}.raw.sarif"
            if os.path.lexists(raw_committed):
                raise VerificationError(
                    f"Raw capture must not be committed: cases/{family_id}/{side}.raw.sarif."
                )
            _verify_promoted_side(
                research_root=research_root,
                capture_files=capture_files,
                family_id=family_id,
                side=side,
                side_value=family.get(side),
                manifest_contract_sha256=manifest_contract_sha256,
            )


def shell_capture_contract(
    *,
    pmd_version: str,
    archive_name: str,
    archive_url: str,
    archive_bytes: int,
    archive_sha256: str,
    archive_prefix: str,
    help_sha256: str,
    python_version: str,
    java_distribution: str,
    java_vendor: str,
    java_version: str,
    runner_label: str,
    runner_image_os: str,
    projection_algorithm_version: str,
    capture_arguments: Sequence[str],
    download_arguments: Sequence[str],
    download_file_size_blocks: int,
) -> dict[str, object]:
    """Build the shell-observed subset in the canonical contract shape."""

    observed = capture_contract()
    producer = _require_mapping(observed.get("producer"), "contract.producer")
    producer.update(
        {
            "version": pmd_version,
            "archiveName": archive_name,
            "archiveUrl": archive_url,
            "archiveBytes": archive_bytes,
            "archiveSha256": archive_sha256,
            "archivePrefix": archive_prefix,
            "helpSha256": help_sha256,
        }
    )
    runtime = _require_mapping(observed.get("runtime"), "contract.runtime")
    runtime.update(
        {
            "pythonVersion": python_version,
            "javaDistribution": java_distribution,
            "javaVendor": java_vendor,
            "javaVersion": java_version,
        }
    )
    runner = _require_mapping(observed.get("runner"), "contract.runner")
    runner.update(
        {
            "label": runner_label,
            "imageOS": runner_image_os,
        }
    )
    observed["projectionAlgorithmVersion"] = projection_algorithm_version
    observed["captureCommand"] = list(capture_arguments)
    download = _require_mapping(observed.get("download"), "contract.download")
    download["command"] = list(download_arguments)
    download["fileSizeLimitBlocks"] = download_file_size_blocks
    return observed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify sparse PMD capture evidence.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    environment = subparsers.add_parser("write-environment")
    environment.add_argument("--output", type=Path, required=True)
    environment.add_argument("--source-sha", required=True)
    environment.add_argument("--image-os", required=True)
    environment.add_argument("--image-version", required=True)
    environment.add_argument("--capture-contract-sha256", required=True)
    contract = subparsers.add_parser("verify-contract")
    contract.add_argument("--pmd-version", required=True)
    contract.add_argument("--archive-name", required=True)
    contract.add_argument("--archive-url", required=True)
    contract.add_argument("--archive-bytes", type=int, required=True)
    contract.add_argument("--archive-sha256", required=True)
    contract.add_argument("--archive-prefix", required=True)
    contract.add_argument("--help-sha256", required=True)
    contract.add_argument("--python-version", required=True)
    contract.add_argument("--java-distribution", required=True)
    contract.add_argument("--java-vendor", required=True)
    contract.add_argument("--java-version", required=True)
    contract.add_argument("--runner-label", required=True)
    contract.add_argument("--runner-image-os", required=True)
    contract.add_argument("--projection-algorithm-version", required=True)
    contract.add_argument("--capture-argument", action="append", required=True)
    contract.add_argument("--download-argument", action="append", required=True)
    contract.add_argument("--download-file-size-blocks", type=int, required=True)
    command = subparsers.add_parser("verify-command")
    command.add_argument("--executable", required=True)
    command.add_argument("--source-root", required=True)
    command.add_argument("--raw-capture", required=True)
    command.add_argument("--ruleset", required=True)
    command.add_argument("--argument", action="append", required=True)
    download = subparsers.add_parser("verify-download-command")
    download.add_argument("--destination", required=True)
    download.add_argument("--file-size-limit-blocks", type=int, required=True)
    download.add_argument("--argument", action="append", required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--research-root", type=Path, required=True)
    verify.add_argument("--capture-root", type=Path, required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--expected-image-os", required=True)
    verify.add_argument("--expected-image-version", required=True)
    promotion = subparsers.add_parser("verify-promotion")
    promotion.add_argument("--research-root", type=Path, required=True)
    promotion.add_argument("--capture-root", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        if parsed.command == "write-environment":
            write_environment_evidence(
                Path(os.path.abspath(parsed.output)),
                parsed.source_sha,
                parsed.image_os,
                parsed.image_version,
                parsed.capture_contract_sha256,
            )
        elif parsed.command == "verify-contract":
            observed = shell_capture_contract(
                pmd_version=parsed.pmd_version,
                archive_name=parsed.archive_name,
                archive_url=parsed.archive_url,
                archive_bytes=parsed.archive_bytes,
                archive_sha256=parsed.archive_sha256,
                archive_prefix=parsed.archive_prefix,
                help_sha256=parsed.help_sha256,
                python_version=parsed.python_version,
                java_distribution=parsed.java_distribution,
                java_vendor=parsed.java_vendor,
                java_version=parsed.java_version,
                runner_label=parsed.runner_label,
                runner_image_os=parsed.runner_image_os,
                projection_algorithm_version=parsed.projection_algorithm_version,
                capture_arguments=parsed.capture_argument,
                download_arguments=parsed.download_argument,
                download_file_size_blocks=parsed.download_file_size_blocks,
            )
            print(verify_capture_contract(observed))
        elif parsed.command == "verify-command":
            verify_capture_command(
                parsed.argument,
                parsed.executable,
                parsed.source_root,
                parsed.raw_capture,
                parsed.ruleset,
            )
        elif parsed.command == "verify-download-command":
            verify_download_command(
                parsed.argument,
                parsed.destination,
                parsed.file_size_limit_blocks,
            )
        elif parsed.command == "verify":
            verify_capture(
                Path(os.path.abspath(parsed.research_root)),
                Path(os.path.abspath(parsed.capture_root)),
                parsed.source_sha,
                parsed.expected_image_os,
                parsed.expected_image_version,
            )
        elif parsed.command == "verify-promotion":
            verify_promotion(
                Path(os.path.abspath(parsed.research_root)),
                Path(os.path.abspath(parsed.capture_root)),
            )
        else:
            raise VerificationError(f"Unsupported verifier command: {parsed.command}.")
    except (OSError, ProjectionError, VerificationError) as error:
        print(f"PMD capture verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
