#!/usr/bin/env python3
"""Verify the byte-frozen source transformations behind the holdout labels.

This verifier is deliberately independent of SarifRegress and producer SARIF.
It reads the source-authored case plans, proves each claimed baseline/candidate
transformation from the controlled source files, and verifies a complete byte
snapshot. It never rewrites repository files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, Mapping, Sequence


MAX_FILE_BYTES: Final = 1024 * 1024
MAX_INPUT_FILES: Final = 256
PRODUCERS: Final = ("gitleaks", "pmd", "semgrep")
RULE_FILES: Final = {
    "gitleaks": "gitleaks.toml",
    "pmd": "pmd-ruleset.xml",
    "semgrep": "semgrep-rules.yml",
}
MARKER_PATTERN: Final = re.compile(
    r"^\s*(?:#|//)\s*HOLDOUT:(?P<semantic_id>[a-z0-9-]+)\s*$"
)
SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(RuntimeError):
    """Raised when committed inputs do not prove the case-plan claim."""


@dataclass(frozen=True, slots=True)
class Occurrence:
    """One marker and its immediately following producer finding line."""

    source_path: PurePosixPath
    marker_line: int
    finding_line: bytes

    @property
    def result_line(self) -> int:
        return self.marker_line + 1


def _read_regular_bounded(path: Path) -> bytes:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"{path} must be a regular non-link file.")
    if metadata.st_size > MAX_FILE_BYTES:
        raise VerificationError(
            f"{path} exceeds the {MAX_FILE_BYTES}-byte input bound."
        )
    with path.open("rb") as stream:
        content = stream.read(MAX_FILE_BYTES + 1)
    if len(content) != metadata.st_size:
        raise VerificationError(f"{path} changed while it was being read.")
    return content


def _read_json(path: Path) -> Mapping[str, Any]:
    content = _read_regular_bounded(path)
    if content.startswith(b"\xef\xbb\xbf"):
        raise VerificationError(f"{path} must not contain a UTF-8 BOM.")
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{path} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(document, dict):
        raise VerificationError(f"{path} must contain a JSON object.")
    return document


def _controlled_inventory(repository_root: Path) -> tuple[Path, ...]:
    cases_root = repository_root / "validation" / "holdout" / "cases"
    inventory: list[Path] = []
    for producer in PRODUCERS:
        case_root = cases_root / producer
        producer_input = case_root / "producer-input"
        inventory.extend(
            (
                case_root / "config.json",
                producer_input / "case-plan.json",
                producer_input / RULE_FILES[producer],
            )
        )
        for side in ("baseline", "candidate"):
            source_root = producer_input / side / "src"
            for directory, directory_names, file_names in os.walk(
                source_root, followlinks=False
            ):
                directory_names.sort()
                file_names.sort()
                directory_path = Path(directory)
                for directory_name in directory_names:
                    child = directory_path / directory_name
                    if child.is_symlink():
                        raise VerificationError(
                            f"controlled source directory {child} must not be a link."
                        )
                for file_name in file_names:
                    inventory.append(directory_path / file_name)
    if len(inventory) > MAX_INPUT_FILES:
        raise VerificationError(
            f"controlled input inventory exceeds {MAX_INPUT_FILES} files."
        )
    for path in inventory:
        _read_regular_bounded(path)
    return tuple(sorted(inventory, key=lambda path: path.as_posix()))


def _verify_byte_snapshot(repository_root: Path, inventory: Sequence[Path]) -> None:
    snapshot_path = (
        repository_root
        / "validation"
        / "tools"
        / "capture"
        / "source-snapshots.sha256"
    )
    snapshot = _read_regular_bounded(snapshot_path)
    expected: dict[PurePosixPath, str] = {}
    for line_number, raw_line in enumerate(snapshot.splitlines(), start=1):
        if not raw_line:
            continue
        try:
            digest_bytes, path_bytes = raw_line.split(b"  ", 1)
            digest = digest_bytes.decode("ascii")
            relative_text = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise VerificationError(
                f"{snapshot_path}:{line_number} is not a checksum entry."
            ) from error
        relative_path = PurePosixPath(relative_text)
        if (
            not SHA256_PATTERN.fullmatch(digest)
            or relative_path.is_absolute()
            or ".." in relative_path.parts
            or relative_path in expected
        ):
            raise VerificationError(
                f"{snapshot_path}:{line_number} is unsafe or duplicated."
            )
        expected[relative_path] = digest

    observed_paths = {
        PurePosixPath(path.relative_to(repository_root).as_posix())
        for path in inventory
    }
    if set(expected) != observed_paths:
        missing = sorted(str(path) for path in observed_paths - set(expected))
        unexpected = sorted(str(path) for path in set(expected) - observed_paths)
        raise VerificationError(
            f"source snapshot inventory mismatch; missing={missing}, "
            f"unexpected={unexpected}."
        )
    for relative_path, expected_digest in sorted(
        expected.items(), key=lambda item: item[0].as_posix()
    ):
        content = _read_regular_bounded(repository_root.joinpath(*relative_path.parts))
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != expected_digest:
            raise VerificationError(
                f"controlled input {relative_path} differs from its byte snapshot."
            )


def _source_occurrences(source_root: Path) -> dict[str, Occurrence]:
    occurrences: dict[str, Occurrence] = {}
    for directory, directory_names, file_names in os.walk(
        source_root, followlinks=False
    ):
        directory_names.sort()
        file_names.sort()
        directory_path = Path(directory)
        for directory_name in directory_names:
            if (directory_path / directory_name).is_symlink():
                raise VerificationError(
                    f"controlled source directory must not be a link: "
                    f"{directory_path / directory_name}."
                )
        for file_name in file_names:
            path = directory_path / file_name
            content = _read_regular_bounded(path)
            if b"\r" in content:
                raise VerificationError(f"{path} must use LF line endings.")
            try:
                lines = content.decode("utf-8").splitlines()
            except UnicodeDecodeError as error:
                raise VerificationError(f"{path} must be UTF-8.") from error
            relative_path = PurePosixPath(path.relative_to(source_root).as_posix())
            for index, line in enumerate(lines):
                marker = MARKER_PATTERN.fullmatch(line)
                if marker is None:
                    continue
                semantic_id = marker.group("semantic_id")
                if semantic_id in occurrences:
                    raise VerificationError(
                        f"duplicate source marker {semantic_id}."
                    )
                if index + 1 >= len(lines) or not lines[index + 1].strip():
                    raise VerificationError(
                        f"{path}:{index + 1} does not immediately precede a finding."
                    )
                if MARKER_PATTERN.fullmatch(lines[index + 1]) is not None:
                    raise VerificationError(
                        f"{path}:{index + 1} precedes another marker."
                    )
                occurrences[semantic_id] = Occurrence(
                    relative_path,
                    index + 1,
                    lines[index + 1].encode("utf-8"),
                )
    return occurrences


def _ambiguity_payload(producer: str, finding_line: bytes) -> bytes:
    stripped = finding_line.strip()
    if producer == "gitleaks":
        if b"=" not in stripped:
            raise VerificationError("Gitleaks ambiguity line lacks an assignment.")
        return stripped.split(b"=", 1)[1]
    return stripped


def _require_same_occurrence(
    semantic_id: str,
    baseline: Occurrence,
    candidate: Occurrence,
    *,
    same_line: bool,
) -> None:
    if baseline.source_path != candidate.source_path:
        raise VerificationError(f"{semantic_id} unexpectedly changed source path.")
    if baseline.finding_line != candidate.finding_line:
        raise VerificationError(f"{semantic_id} unexpectedly changed finding source.")
    if same_line and baseline.result_line != candidate.result_line:
        raise VerificationError(f"{semantic_id} unexpectedly changed line number.")


def _source_lines(source_root: Path, occurrence: Occurrence) -> tuple[bytes, ...]:
    content = _read_regular_bounded(
        source_root.joinpath(*occurrence.source_path.parts)
    )
    return tuple(content.splitlines())


def _controlled_insertions_before_marker(
    source_root: Path, occurrence: Occurrence
) -> int:
    lines = _source_lines(source_root, occurrence)
    marker_index = occurrence.marker_line - 1
    count = 0
    for line in reversed(lines[:marker_index]):
        if b"Controlled insert" not in line:
            break
        count += 1
    return count


def _without_controlled_insertions(lines: Sequence[bytes]) -> list[bytes]:
    return sorted(line for line in lines if b"Controlled insert" not in line)


def _verify_producer(repository_root: Path, producer: str) -> None:
    producer_input = (
        repository_root
        / "validation"
        / "holdout"
        / "cases"
        / producer
        / "producer-input"
    )
    plan = _read_json(producer_input / "case-plan.json")
    if plan.get("schemaVersion") != "1" or plan.get("producer") != producer:
        raise VerificationError(f"{producer} case plan identity is invalid.")
    entries = plan.get("entries")
    if not isinstance(entries, list) or len(entries) != 33:
        raise VerificationError(f"{producer} case plan must contain 33 entries.")

    baseline = _source_occurrences(producer_input / "baseline" / "src")
    candidate = _source_occurrences(producer_input / "candidate" / "src")
    baseline_source_root = producer_input / "baseline" / "src"
    candidate_source_root = producer_input / "candidate" / "src"
    planned_ids: set[str] = set()
    ambiguous_occurrences: list[tuple[Occurrence, Occurrence]] = []
    for index, raw_entry in enumerate(entries):
        if not isinstance(raw_entry, dict):
            raise VerificationError(f"{producer} plan entry {index} is not an object.")
        semantic_id = raw_entry.get("semanticId")
        scenario = raw_entry.get("scenario")
        presence = raw_entry.get("presence")
        if not isinstance(semantic_id, str) or not semantic_id.startswith(
            f"{producer}-"
        ):
            raise VerificationError(f"{producer} plan entry {index} has bad identity.")
        if semantic_id in planned_ids:
            raise VerificationError(f"duplicate planned identity {semantic_id}.")
        planned_ids.add(semantic_id)

        baseline_occurrence = baseline.get(semantic_id)
        candidate_occurrence = candidate.get(semantic_id)
        if presence == "baseline":
            if baseline_occurrence is None or candidate_occurrence is not None:
                raise VerificationError(
                    f"{semantic_id} does not prove a controlled removal."
                )
            continue
        if presence == "candidate":
            if candidate_occurrence is None or baseline_occurrence is not None:
                raise VerificationError(
                    f"{semantic_id} does not prove a controlled addition."
                )
            continue
        if presence != "both" or baseline_occurrence is None or candidate_occurrence is None:
            raise VerificationError(f"{semantic_id} has inconsistent side presence.")

        if scenario in {"exact", "message-modified", "ambiguous"}:
            _require_same_occurrence(
                semantic_id,
                baseline_occurrence,
                candidate_occurrence,
                same_line=True,
            )
            if scenario == "ambiguous":
                ambiguous_occurrences.append(
                    (baseline_occurrence, candidate_occurrence)
                )
        elif scenario in {"line-shift", "moved"}:
            _require_same_occurrence(
                semantic_id,
                baseline_occurrence,
                candidate_occurrence,
                same_line=False,
            )
            if candidate_occurrence.result_line <= baseline_occurrence.result_line:
                raise VerificationError(
                    f"{semantic_id} does not prove a downward source move."
                )
            if scenario == "line-shift":
                expected_insertions = int(semantic_id.rsplit("-", 1)[1])
                if (
                    _controlled_insertions_before_marker(
                        baseline_source_root, baseline_occurrence
                    )
                    != 0
                    or _controlled_insertions_before_marker(
                        candidate_source_root, candidate_occurrence
                    )
                    != expected_insertions
                ):
                    raise VerificationError(
                        f"{semantic_id} does not prove its exact inserted-line count."
                    )
                expected_line_delta = sum(
                    _controlled_insertions_before_marker(
                        candidate_source_root,
                        other_occurrence,
                    )
                    for other_id, other_occurrence in candidate.items()
                    if other_id.startswith(f"{producer}-line-shift-")
                    and other_occurrence.source_path
                    == candidate_occurrence.source_path
                    and other_occurrence.marker_line
                    <= candidate_occurrence.marker_line
                )
                actual_line_delta = (
                    candidate_occurrence.result_line
                    - baseline_occurrence.result_line
                )
                if actual_line_delta != expected_line_delta:
                    raise VerificationError(
                        f"{semantic_id} line delta is {actual_line_delta}, "
                        f"expected cumulative controlled delta "
                        f"{expected_line_delta}."
                    )
            elif _without_controlled_insertions(
                _source_lines(baseline_source_root, baseline_occurrence)
            ) != _without_controlled_insertions(
                _source_lines(candidate_source_root, candidate_occurrence)
            ):
                raise VerificationError(
                    f"{semantic_id} changes content instead of only moving it."
                )
        elif scenario == "renamed":
            baseline_parts = baseline_occurrence.source_path.parts
            if baseline_parts.count("renamed-old") != 1:
                raise VerificationError(
                    f"{semantic_id} baseline path lacks one renamed-old component."
                )
            expected_candidate_path = PurePosixPath(
                *(
                    "renamed-new" if part == "renamed-old" else part
                    for part in baseline_parts
                )
            )
            if (
                expected_candidate_path == baseline_occurrence.source_path
                or candidate_occurrence.source_path != expected_candidate_path
                or candidate_occurrence.result_line != baseline_occurrence.result_line
                or candidate_occurrence.finding_line != baseline_occurrence.finding_line
            ):
                raise VerificationError(
                    f"{semantic_id} does not prove the controlled directory rename."
                )
            baseline_file = baseline_source_root.joinpath(
                *baseline_occurrence.source_path.parts
            )
            candidate_file = candidate_source_root.joinpath(
                *candidate_occurrence.source_path.parts
            )
            if _read_regular_bounded(baseline_file) != _read_regular_bounded(
                candidate_file
            ):
                raise VerificationError(
                    f"{semantic_id} renamed file bytes are not identical."
                )
        else:
            raise VerificationError(
                f"{semantic_id} has unsupported transformation {scenario!r}."
            )

    if set(baseline) | set(candidate) != planned_ids:
        raise VerificationError(f"{producer} has unplanned or missing source markers.")
    expected_baseline = {
        raw_entry["semanticId"]
        for raw_entry in entries
        if raw_entry.get("presence") in {"both", "baseline"}
    }
    expected_candidate = {
        raw_entry["semanticId"]
        for raw_entry in entries
        if raw_entry.get("presence") in {"both", "candidate"}
    }
    if set(baseline) != expected_baseline or set(candidate) != expected_candidate:
        raise VerificationError(f"{producer} source presence differs from its plan.")
    if len(ambiguous_occurrences) != 2:
        raise VerificationError(f"{producer} must have exactly two ambiguity members.")
    for side_index in (0, 1):
        ambiguity_payloads = {
            _ambiguity_payload(producer, pair[side_index].finding_line)
            for pair in ambiguous_occurrences
        }
        if len(ambiguity_payloads) != 1:
            raise VerificationError(
                f"{producer} ambiguity members do not share producer-visible content."
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify byte-frozen independent-holdout source transformations."
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        repository_root = parsed.repository_root.resolve(strict=True)
        inventory = _controlled_inventory(repository_root)
        _verify_byte_snapshot(repository_root, inventory)
        for producer in PRODUCERS:
            _verify_producer(repository_root, producer)
    except (OSError, VerificationError) as error:
        print(f"source transformation verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Verified byte-frozen source transformations for gitleaks, pmd, and semgrep."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
