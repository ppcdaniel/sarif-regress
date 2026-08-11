#!/usr/bin/env python3
"""Project only ambient checkout prefixes from authentic PMD SARIF URIs."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Final, Mapping, Sequence
from urllib.parse import unquote_to_bytes, urlsplit


ALGORITHM_VERSION: Final = "pmd-file-uri-prefix-projection/v1"
MAX_JSON_BYTES: Final = 16 * 1024 * 1024
MAX_JSON_DEPTH: Final = 96
MAX_JSON_NODES: Final = 500_000
MAX_RESULTS: Final = 10_000
MAX_PROJECTED_LOCATIONS: Final = 10_000
STABLE_ID_PATTERN: Final = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
POSIX_LOCAL_PATH_PATTERN: Final = re.compile(
    r"(?ix)(?:"
    r"(?<![A-Za-z0-9+.\-:/])file:/+[^\s\"'<>]+|"
    r"(?<![A-Za-z0-9+.\-:/])//(?:"
    r"(?=$|[\s\"'<>),;\]}])|"
    r"[^/\s\"'<>]+(?:/[^/\s\"'<>]+)*)|"
    r"(?<![A-Za-z0-9+.\-:/])/(?!/)(?:"
    r"(?=$|[\s\"'<>),;\]}])|"
    r"[^/\s\"'<>]+(?:/[^/\s\"'<>]+)*))"
)
WINDOWS_LOCAL_PATH_PATTERN: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:"
    r"[A-Za-z]:[\\/]|\\\\(?:\?|\.)[\\/]|\\\\[^\\/\s]+[\\/])"
)
TIMESTAMP_PATTERN: Final = re.compile(
    r"\b[12][0-9]{3}-[01][0-9]-[0-3][0-9]"
    r"T[0-2][0-9]:[0-5][0-9]:[0-6][0-9](?:\.[0-9]+)?"
    r"(?:Z|[+-][0-2][0-9]:[0-5][0-9])\b"
)
HOST_VALUE_PATTERN: Final = re.compile(
    r"(?ix)^(?:localhost|fv-az[a-z0-9-]*|desktop-[a-z0-9-]+|"
    r"runner(?:-[a-z0-9-]+)?|ip-[0-9-]+|[a-z0-9-]+\.local)$"
)
EMBEDDED_HOST_PATTERN: Final = re.compile(
    r"(?ix)(?<![a-z0-9.\-])(?:localhost|fv-az[a-z0-9-]*|"
    r"desktop-[a-z0-9-]+|runner-[a-z0-9-]+|ip-[0-9-]+|"
    r"[a-z0-9-]+\.local)(?![a-z0-9.\-])"
)
HOST_KEYS: Final = frozenset({"hostname", "machinename", "computername", "host"})
JSON_POINTER_PATTERN: Final = re.compile(r"(?:/(?:[^~/]|~[01])*)*")


class ProjectionError(RuntimeError):
    """Raised when an authentic capture cannot be projected without guessing."""


class _DuplicateKeyError(ValueError):
    """Raised for a duplicate JSON object member."""


def sha256_bytes(payload: bytes) -> str:
    """Return a lowercase SHA-256 digest."""

    return hashlib.sha256(payload).hexdigest()


def stable_json_bytes(value: object, *, sort_keys: bool) -> bytes:
    """Serialize deterministic strict JSON with a single trailing LF."""

    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=sort_keys,
        )
        + "\n"
    ).encode("utf-8")


def _read_regular_bounded(path: Path) -> bytes:
    try:
        status = path.lstat()
    except OSError as error:
        raise ProjectionError(f"Cannot inspect {path}.") from error
    if stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise ProjectionError(f"Input must be a regular non-link file: {path}.")
    if status.st_size <= 0 or status.st_size > MAX_JSON_BYTES:
        raise ProjectionError(
            f"Input {path} has disallowed size {status.st_size}; maximum is "
            f"{MAX_JSON_BYTES}."
        )

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ProjectionError(f"Input changed to a non-regular file: {path}.")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(1024 * 1024, MAX_JSON_BYTES + 1 - observed),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > MAX_JSON_BYTES:
                    raise ProjectionError(
                        f"Input {path} exceeds {MAX_JSON_BYTES} bytes."
                    )
            payload = b"".join(chunks)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ProjectionError(f"Cannot safely read {path}.") from error
    return payload


def read_strict_json(path: Path) -> tuple[object, bytes]:
    """Read bounded duplicate-free UTF-8 JSON and enforce structural limits."""

    payload = _read_regular_bounded(path)
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ProjectionError(f"JSON input has a UTF-8 BOM: {path}.")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProjectionError(f"JSON input is not strict UTF-8: {path}.") from error

    # CPython's decoder may recurse before a parsed tree exists. Reject excess
    # container nesting with a string-aware lexical pass first so the semantic
    # limit is also an allocation/stack limit rather than a post-hoc diagnostic.
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ProjectionError(
                    f"JSON input exceeds depth {MAX_JSON_DEPTH}: {path}."
                )
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ProjectionError(f"JSON input has unbalanced containers: {path}.")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateKeyError(key)
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"non-standard numeric constant {value}")

    try:
        document = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except _DuplicateKeyError as error:
        raise ProjectionError(
            f"JSON input contains duplicate key {error.args[0]!r}: {path}."
        ) from error
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ProjectionError(f"JSON input is invalid or too deeply nested: {path}.") from error

    nodes = 0
    stack: list[tuple[object, int]] = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ProjectionError(
                f"JSON input exceeds {MAX_JSON_NODES} structural nodes: {path}."
            )
        if depth > MAX_JSON_DEPTH:
            raise ProjectionError(
                f"JSON input exceeds depth {MAX_JSON_DEPTH}: {path}."
            )
        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
    return document, payload


def _require_mapping(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ProjectionError(f"{context} must be an object.")
    return value


def _require_list(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ProjectionError(f"{context} must be an array.")
    return value


def _canonical_absolute_path(path: Path, context: str) -> Path:
    value = os.fspath(path)
    if "\x00" in value or "\\" in value or not os.path.isabs(value):
        raise ProjectionError(f"{context} must be a canonical absolute POSIX path.")
    normalized = os.path.normpath(value)
    if normalized != value:
        raise ProjectionError(f"{context} is not lexically canonical.")
    return Path(value)


def _open_anchored_directory(path: Path) -> int:
    """Open an absolute directory without following any path component."""

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ProjectionError("No-follow directory handles are unavailable on this host.")
    canonical = _canonical_absolute_path(path, "source root")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in canonical.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        status = os.fstat(descriptor)
        if not stat.S_ISDIR(status.st_mode):
            raise ProjectionError("Source root handle is not a directory.")
        return descriptor
    except (OSError, ProjectionError) as error:
        os.close(descriptor)
        if isinstance(error, ProjectionError):
            raise
        raise ProjectionError(
            "Source root or one of its ancestors is missing, linked, or inaccessible."
        ) from error


def _assert_source_file(source_root_descriptor: int, relative: Path) -> None:
    descriptor = os.dup(source_root_descriptor)
    try:
        for index, part in enumerate(relative.parts):
            final = index == len(relative.parts) - 1
            if part in {"", ".", ".."}:
                raise ProjectionError("A PMD artifact URI contains an unsafe path segment.")
            flags = os.O_RDONLY | os.O_NOFOLLOW
            if not final:
                flags |= os.O_DIRECTORY
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise ProjectionError(f"PMD artifact is not a regular source file: {relative}.")
    except OSError as error:
        raise ProjectionError(
            f"PMD artifact is missing, linked, or inaccessible: {relative}."
        ) from error
    finally:
        os.close(descriptor)


def _project_file_uri(
    uri: str,
    source_root: Path,
    source_root_descriptor: int,
) -> str:
    try:
        parsed = urlsplit(uri)
    except ValueError as error:
        raise ProjectionError("PMD artifact URI is malformed.") from error
    if parsed.scheme.casefold() != "file" or parsed.netloc:
        raise ProjectionError(
            "PMD artifact URI must be a local absolute file URI with no authority."
        )
    if parsed.query or parsed.fragment:
        raise ProjectionError("PMD artifact file URI must not contain a query or fragment.")
    try:
        decoded = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ProjectionError("PMD artifact URI path is not strict UTF-8.") from error
    if "\x00" in decoded or "\\" in decoded:
        raise ProjectionError("PMD artifact URI contains a prohibited path character.")
    absolute = Path(decoded)
    if not absolute.is_absolute():
        raise ProjectionError("PMD artifact file URI is not absolute.")
    try:
        relative = absolute.relative_to(source_root)
    except ValueError as error:
        raise ProjectionError(
            "PMD artifact file URI is outside the selected side source root."
        ) from error
    if not relative.parts:
        raise ProjectionError("PMD artifact URI resolves to the source directory itself.")
    _assert_source_file(source_root_descriptor, relative)
    portable = PurePosixPath(*relative.parts).as_posix()
    if portable.startswith("/") or ".." in PurePosixPath(portable).parts:
        raise ProjectionError("Projected PMD artifact URI is not safely relative.")
    return portable


def assert_portable_deterministic_sarif(value: object, source_root: Path) -> None:
    """Reject ambient machine data from a deterministic projected SARIF value."""

    source_text = os.fspath(source_root)
    stack: list[tuple[object, str | None]] = [(value, None)]
    while stack:
        current, key = stack.pop()
        if isinstance(current, dict):
            stack.extend((child, child_key) for child_key, child in current.items())
            continue
        if isinstance(current, list):
            stack.extend((child, key) for child in current)
            continue
        if not isinstance(current, str):
            continue
        normalized_key = re.sub(r"[-_]", "", key or "").casefold()
        is_typed_pointer = (
            normalized_key == "jsonpointer"
            and JSON_POINTER_PATTERN.fullmatch(current) is not None
        )
        if source_text in current or (
            not is_typed_pointer
            and (
                POSIX_LOCAL_PATH_PATTERN.search(current)
                or WINDOWS_LOCAL_PATH_PATTERN.search(current)
            )
        ):
            raise ProjectionError(
                "Projected SARIF retains an absolute local path or file URI."
            )
        if TIMESTAMP_PATTERN.search(current):
            raise ProjectionError("Projected SARIF retains a wall-clock timestamp.")
        if (
            normalized_key in HOST_KEYS
            or HOST_VALUE_PATTERN.fullmatch(current)
            or EMBEDDED_HOST_PATTERN.search(current)
        ):
            raise ProjectionError("Projected SARIF retains a machine hostname.")


def project_document(
    raw_document: object,
    source_root: Path,
) -> tuple[dict[str, object], list[dict[str, object]], int]:
    """Return a copy changing only controlled primary artifact URI strings."""

    source_root = _canonical_absolute_path(source_root, "source root")
    source_root_descriptor = _open_anchored_directory(source_root)
    raw = _require_mapping(raw_document, "SARIF document")
    if raw.get("version") != "2.1.0":
        raise ProjectionError("Capture is not SARIF 2.1.0.")
    projected = copy.deepcopy(raw)
    runs = _require_list(projected.get("runs"), "SARIF runs")
    changes: list[dict[str, object]] = []
    result_count = 0
    try:
        for run_index, run_value in enumerate(runs):
            run = _require_mapping(run_value, f"runs[{run_index}]")
            results = _require_list(run.get("results"), f"runs[{run_index}].results")
            result_count += len(results)
            if result_count > MAX_RESULTS:
                raise ProjectionError(f"Capture exceeds {MAX_RESULTS} PMD results.")
            for result_index, result_value in enumerate(results):
                result = _require_mapping(
                    result_value,
                    f"runs[{run_index}].results[{result_index}]",
                )
                locations = _require_list(
                    result.get("locations"),
                    f"runs[{run_index}].results[{result_index}].locations",
                )
                if not locations:
                    raise ProjectionError("Every PMD result must contain a physical location.")
                for location_index, location_value in enumerate(locations):
                    if len(changes) >= MAX_PROJECTED_LOCATIONS:
                        raise ProjectionError(
                            "Capture exceeds the projected-location evidence limit."
                        )
                    location = _require_mapping(
                        location_value,
                        f"runs[{run_index}].results[{result_index}].locations[{location_index}]",
                    )
                    physical = _require_mapping(
                        location.get("physicalLocation"),
                        "PMD result physicalLocation",
                    )
                    artifact = _require_mapping(
                        physical.get("artifactLocation"),
                        "PMD result artifactLocation",
                    )
                    original_uri = artifact.get("uri")
                    if not isinstance(original_uri, str) or not original_uri:
                        raise ProjectionError("PMD result artifact URI must be a string.")
                    projected_uri = _project_file_uri(
                        original_uri,
                        source_root,
                        source_root_descriptor,
                    )
                    artifact["uri"] = projected_uri
                    pointer = (
                        f"/runs/{run_index}/results/{result_index}/locations/"
                        f"{location_index}/physicalLocation/artifactLocation/uri"
                    )
                    changes.append(
                        {
                            "kind": "checkout-file-uri-prefix-removal",
                            "pointer": pointer,
                            "originalValueSha256": sha256_bytes(original_uri.encode("utf-8")),
                            "projectedValue": projected_uri,
                        }
                    )
    finally:
        os.close(source_root_descriptor)
    if result_count == 0 or not changes:
        raise ProjectionError("Capture contains no projectable PMD results.")
    assert_portable_deterministic_sarif(projected, source_root)
    return projected, changes, result_count


def build_audit(
    *,
    family_id: str,
    side: str,
    logical_source_root: str,
    raw_payload: bytes,
    projected_payload: bytes,
    changes: Sequence[Mapping[str, object]],
    result_count: int,
    capture_contract_sha256: str,
) -> dict[str, object]:
    """Build checkout-path-free projection evidence."""

    if side not in {"baseline", "candidate"}:
        raise ProjectionError(f"Unsupported capture side: {side}.")
    if "\\" in logical_source_root:
        raise ProjectionError("Logical source root must not contain backslashes.")
    logical = PurePosixPath(logical_source_root)
    if (
        logical.is_absolute()
        or ".." in logical.parts
        or not logical.parts
        or logical.as_posix() != logical_source_root
    ):
        raise ProjectionError("Logical source root must be safely relative.")
    if STABLE_ID_PATTERN.fullmatch(family_id) is None:
        raise ProjectionError("Family ID is not stable and portable.")
    if SHA256_PATTERN.fullmatch(capture_contract_sha256) is None:
        raise ProjectionError("Capture contract SHA-256 is invalid.")
    return {
        "schemaVersion": "1",
        "algorithmVersion": ALGORITHM_VERSION,
        "captureContractSha256": capture_contract_sha256,
        "familyId": family_id,
        "side": side,
        "logicalSourceRoot": logical.as_posix(),
        "rawSarif": {
            "bytes": len(raw_payload),
            "sha256": sha256_bytes(raw_payload),
        },
        "projectedSarif": {
            "bytes": len(projected_payload),
            "sha256": sha256_bytes(projected_payload),
            "resultCount": result_count,
        },
        "changes": list(changes),
    }


def _write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)


def project_capture(
    input_path: Path,
    output_path: Path,
    audit_path: Path,
    source_root: Path,
    family_id: str,
    side: str,
    logical_source_root: str,
    capture_contract_sha256: str,
) -> None:
    """Project one capture without modifying its raw bytes."""

    raw_document, raw_payload = read_strict_json(input_path)
    raw_sha256 = sha256_bytes(raw_payload)
    projected, changes, result_count = project_document(raw_document, source_root)
    projected_payload = stable_json_bytes(projected, sort_keys=False)
    audit = build_audit(
        family_id=family_id,
        side=side,
        logical_source_root=logical_source_root,
        raw_payload=raw_payload,
        projected_payload=projected_payload,
        changes=changes,
        result_count=result_count,
        capture_contract_sha256=capture_contract_sha256,
    )
    _write_new(output_path, projected_payload)
    _write_new(audit_path, stable_json_bytes(audit, sort_keys=True))
    if sha256_bytes(_read_regular_bounded(input_path)) != raw_sha256:
        raise ProjectionError("Raw PMD SARIF changed during projection.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Remove only the ambient source-root prefix from PMD file URIs."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--logical-source-root", required=True)
    parser.add_argument("--family-id", required=True)
    parser.add_argument("--side", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--capture-contract-sha256", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        project_capture(
            Path(os.path.abspath(parsed.input)),
            Path(os.path.abspath(parsed.output)),
            Path(os.path.abspath(parsed.audit)),
            Path(os.path.abspath(parsed.source_root)),
            parsed.family_id,
            parsed.side,
            parsed.logical_source_root,
            parsed.capture_contract_sha256,
        )
    except (OSError, ProjectionError) as error:
        print(f"PMD SARIF projection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
