#!/usr/bin/env python3
"""Deterministically refresh sparse-research implementation and integrity manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable, Mapping, Sequence

from scan_contamination import (
    EXPERIMENT_IMPLEMENTATION_KIND,
    EXPERIMENT_IMPLEMENTATION_ROOT_FILES,
    EXPERIMENT_IMPLEMENTATION_ROOTS,
    MAX_DIRECTORIES,
    MAX_FILES,
    MAX_TOTAL_BYTES,
)


IMPLEMENTATION_FILE_LIMIT: Final = 256
IMPLEMENTATION_FILE_BYTE_LIMIT: Final = 4 * 1024 * 1024
MANIFEST_BYTE_LIMIT: Final = 2 * 1024 * 1024
READ_CHUNK_BYTES: Final = 64 * 1024
MAXIMUM_RELATIVE_PATH_CHARACTERS: Final = 512
SPARSE_ROOT_RELATIVE: Final = Path("validation/research/sparse-sarif")
IMPLEMENTATION_MANIFEST_NAME: Final = "experiment-implementation-manifest.json"
CORPUS_MANIFEST_NAME: Final = "manifest.json"
IMPLEMENTATION_RELATIVE_PATH_PATTERN: Final = re.compile(
    r"^(?:Directory\.Build\.props|Directory\.Packages\.props|global\.json|"
    r"(?:src/SarifRegress\.(?:Cli|Core|Match|Report|Sarif)|"
    r"validation/tools/SarifRegress\.Validation)/"
    r"(?!.*(?:^|/)(?:bin|obj)/)(?:[A-Za-z0-9._-]+/)*"
    r"(?:[A-Za-z0-9._-]+\.cs|[A-Za-z0-9._-]+\.csproj|packages\.lock\.json))$",
    re.ASCII,
)


class ManifestRefreshError(RuntimeError):
    """Raised when the source tree cannot be inventoried without ambiguity."""


@dataclass(frozen=True)
class ManifestUpdate:
    """Represents the exact expected bytes for one tracked manifest."""

    path: Path
    expected_bytes: bytes
    actual_bytes: bytes

    @property
    def is_current(self) -> bool:
        """Return whether the tracked manifest already has the expected bytes."""

        return self.actual_bytes == self.expected_bytes


def _is_reparse_point(path: Path, status: os.stat_result) -> bool:
    """Return whether a path is a Windows reparse point or junction."""

    file_attributes = getattr(status, "st_file_attributes", 0)
    reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    junction_probe = getattr(path, "is_junction", None)
    return bool(file_attributes & reparse_attribute) or bool(
        callable(junction_probe) and junction_probe()
    )


def _require_directory(path: Path, description: str) -> None:
    """Require an existing physical directory without following a link."""

    try:
        status = path.lstat()
    except OSError as error:
        raise ManifestRefreshError(f"Cannot inspect {description}: {path}") from error
    if (
        stat.S_ISLNK(status.st_mode)
        or not stat.S_ISDIR(status.st_mode)
        or _is_reparse_point(path, status)
    ):
        raise ManifestRefreshError(
            f"{description.capitalize()} must be a non-link directory: {path}"
        )


def _require_repository_path_ancestors(
    repository_root: Path,
    path: Path,
    description: str,
) -> None:
    """Reject linked or special ancestors between a physical root and a path."""

    try:
        relative = path.relative_to(repository_root)
    except ValueError as error:
        raise ManifestRefreshError(
            f"{description.capitalize()} is outside the physical repository: {path}"
        ) from error

    current = repository_root
    for component in relative.parts[:-1]:
        if component in {"", ".", ".."}:
            raise ManifestRefreshError(
                f"{description.capitalize()} has an invalid path component: {path}"
            )
        current /= component
        _require_directory(current, f"{description} ancestor")


def _require_valid_implementation_relative_path(relative: str) -> None:
    """Require the exact portable path contract accepted by the manifest schema."""

    if not 1 <= len(relative) <= MAXIMUM_RELATIVE_PATH_CHARACTERS:
        raise ManifestRefreshError(
            "Implementation path exceeds its 512-character schema bound: "
            + repr(relative)
        )
    if IMPLEMENTATION_RELATIVE_PATH_PATTERN.fullmatch(relative) is None:
        raise ManifestRefreshError(
            "Implementation path does not satisfy the portable ASCII schema contract: "
            + repr(relative)
        )


def _read_stable_file(path: Path, maximum_bytes: int) -> bytes:
    """Read a bounded regular file while detecting replacement during the read."""

    try:
        before_path = path.lstat()
    except OSError as error:
        raise ManifestRefreshError(f"Cannot inspect file: {path}") from error
    if (
        stat.S_ISLNK(before_path.st_mode)
        or not stat.S_ISREG(before_path.st_mode)
        or _is_reparse_point(path, before_path)
    ):
        raise ManifestRefreshError(f"Manifest inputs must be regular non-link files: {path}")
    if before_path.st_size > maximum_bytes:
        raise ManifestRefreshError(
            f"Manifest input exceeds its {maximum_bytes}-byte bound: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum_bytes:
            raise ManifestRefreshError(f"Manifest input changed before reading: {path}")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, READ_CHUNK_BYTES))
            if not chunk:
                raise ManifestRefreshError(f"Manifest input was truncated while reading: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ManifestRefreshError(f"Manifest input grew while reading: {path}")
        after = os.fstat(descriptor)
    except OSError as error:
        raise ManifestRefreshError(f"Cannot read manifest input: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)

    before_identity = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    after_identity = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    try:
        after_path = path.lstat()
    except OSError as error:
        raise ManifestRefreshError(f"Manifest input disappeared after reading: {path}") from error
    path_identity = (
        after_path.st_dev,
        after_path.st_ino,
        after_path.st_size,
        after_path.st_mtime_ns,
    )
    if before_identity != after_identity or after_identity != path_identity:
        raise ManifestRefreshError(f"Manifest input changed while reading: {path}")
    return b"".join(chunks)


def _walk_regular_files(
    root: Path,
    *,
    excluded_directory_names: frozenset[str] = frozenset(),
) -> Iterable[Path]:
    """Yield physical files while rejecting links and bounding traversal.

    Time: O(D + F), where D is directories and F is directory entries.
    Space: O(D), as ``os.walk`` retains only its traversal frontier.
    """

    directory_count = 0
    file_count = 0
    entry_count = 0
    for directory, names, filenames in os.walk(root, topdown=True, followlinks=False):
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            raise ManifestRefreshError(
                f"Directory inventory exceeds its {MAX_DIRECTORIES}-directory bound."
            )
        directory_path = Path(directory)
        names.sort()
        filenames.sort()
        for name in names:
            entry_count += 1
            child = directory_path / name
            try:
                child_status = child.lstat()
            except OSError as error:
                raise ManifestRefreshError(f"Cannot inspect directory entry: {child}") from error
            if (
                stat.S_ISLNK(child_status.st_mode)
                or not stat.S_ISDIR(child_status.st_mode)
                or _is_reparse_point(child, child_status)
            ):
                raise ManifestRefreshError(
                    f"Manifest inventory cannot contain links or special directories: {child}"
                )
        names[:] = [name for name in names if name not in excluded_directory_names]
        for name in filenames:
            file_count += 1
            if file_count > MAX_FILES:
                raise ManifestRefreshError(
                    f"File inventory exceeds its {MAX_FILES}-file bound."
                )
            entry_count += 1
            path = directory_path / name
            try:
                file_status = path.lstat()
            except OSError as error:
                raise ManifestRefreshError(f"Cannot inspect file entry: {path}") from error
            if (
                stat.S_ISLNK(file_status.st_mode)
                or not stat.S_ISREG(file_status.st_mode)
                or _is_reparse_point(path, file_status)
            ):
                raise ManifestRefreshError(
                    f"Manifest inventory cannot contain links or special files: {path}"
                )
            yield path
        if entry_count > MAX_FILES + MAX_DIRECTORIES:
            raise ManifestRefreshError("Manifest inventory contains too many entries.")


def _implementation_paths(repository_root: Path) -> tuple[str, ...]:
    """Return the exact ordinal implementation inventory used by validation.

    Time: O(D + F log F), dominated by sorting the selected file paths.
    Space: O(F), bounded to 256 admitted implementation files.
    """

    paths = list(EXPERIMENT_IMPLEMENTATION_ROOT_FILES)
    for relative in paths:
        _require_valid_implementation_relative_path(relative)
    for relative_root in EXPERIMENT_IMPLEMENTATION_ROOTS:
        root = repository_root / relative_root
        _require_repository_path_ancestors(
            repository_root,
            root,
            f"implementation root '{relative_root}'",
        )
        _require_directory(root, f"implementation root '{relative_root}'")
        for path in _walk_regular_files(
            root,
            excluded_directory_names=frozenset({"bin", "obj"}),
        ):
            name = path.name
            if not (
                name.endswith(".cs")
                or name.endswith(".csproj")
                or name == "packages.lock.json"
            ):
                continue
            relative = path.relative_to(repository_root).as_posix()
            _require_valid_implementation_relative_path(relative)
            paths.append(relative)
            if len(paths) > IMPLEMENTATION_FILE_LIMIT:
                raise ManifestRefreshError(
                    "Implementation inventory exceeds its 256-file contract bound."
                )

    for relative in EXPERIMENT_IMPLEMENTATION_ROOT_FILES:
        path = repository_root / relative
        _require_repository_path_ancestors(
            repository_root,
            path,
            f"implementation root file '{relative}'",
        )
        _read_stable_file(path, IMPLEMENTATION_FILE_BYTE_LIMIT)
    if len(paths) != len(set(paths)):
        raise ManifestRefreshError("Implementation inventory contains duplicate paths.")
    return tuple(sorted(paths))


def _serialize_json(value: Mapping[str, object]) -> bytes:
    """Serialize a manifest using the repository's canonical UTF-8 layout."""

    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _build_implementation_manifest(repository_root: Path) -> bytes:
    """Build exact implementation inventory bytes from the current source tree."""

    files = []
    for relative in _implementation_paths(repository_root):
        path = repository_root / relative
        _require_repository_path_ancestors(
            repository_root,
            path,
            f"implementation file '{relative}'",
        )
        payload = _read_stable_file(
            path,
            IMPLEMENTATION_FILE_BYTE_LIMIT,
        )
        files.append({"path": relative, "sha256": hashlib.sha256(payload).hexdigest()})
    return _serialize_json(
        {
            "schemaVersion": "1",
            "kind": EXPERIMENT_IMPLEMENTATION_KIND,
            "algorithm": "sha256",
            "files": files,
        }
    )


def _corpus_integrity_paths(sparse_root: Path) -> tuple[str, ...]:
    """Return every integrity-covered corpus path in ordinal order."""

    paths: list[str] = []
    total_bytes = 0
    for path in _walk_regular_files(sparse_root):
        relative = path.relative_to(sparse_root).as_posix()
        if len(relative) > MAXIMUM_RELATIVE_PATH_CHARACTERS:
            raise ManifestRefreshError(
                "Corpus integrity path exceeds its 512-character schema bound: "
                + relative
            )
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            raise ManifestRefreshError(
                "Python bytecode is not an admitted corpus input; rerun with -B: "
                + relative
            )
        file_size = path.lstat().st_size
        total_bytes += file_size
        if total_bytes > MAX_TOTAL_BYTES:
            raise ManifestRefreshError(
                f"Sparse inventory exceeds its {MAX_TOTAL_BYTES}-byte tree bound."
            )
        if relative == CORPUS_MANIFEST_NAME or relative.startswith("expected/"):
            continue
        paths.append(relative)
        if len(paths) > MAX_FILES:
            raise ManifestRefreshError(
                f"Corpus integrity inventory exceeds its {MAX_FILES}-file bound."
            )
    if len(paths) != len(set(paths)):
        raise ManifestRefreshError("Corpus integrity inventory contains duplicate paths.")
    return tuple(sorted(paths))


def _load_corpus_manifest(path: Path) -> dict[str, object]:
    """Load the current corpus manifest without accepting duplicate JSON keys."""

    def reject_duplicate_pairs(pairs: Sequence[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ManifestRefreshError(f"Corpus manifest repeats JSON property '{key}'.")
            result[key] = value
        return result

    payload = _read_stable_file(path, MANIFEST_BYTE_LIMIT)
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ManifestRefreshError("Corpus manifest is not valid UTF-8 JSON.") from error
    if not isinstance(value, dict):
        raise ManifestRefreshError("Corpus manifest root must be an object.")
    integrity = value.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
        raise ManifestRefreshError("Corpus manifest has an unsupported integrity contract.")
    return value


def _build_corpus_manifest(
    repository_root: Path,
    implementation_manifest_bytes: bytes,
) -> bytes:
    """Refresh complete corpus integrity coverage while preserving corpus metadata."""

    sparse_root = repository_root / SPARSE_ROOT_RELATIVE
    manifest_path = sparse_root / CORPUS_MANIFEST_NAME
    manifest = _load_corpus_manifest(manifest_path)
    integrity_files: list[dict[str, str]] = []
    for relative in _corpus_integrity_paths(sparse_root):
        if relative == IMPLEMENTATION_MANIFEST_NAME:
            payload = implementation_manifest_bytes
        else:
            payload = _read_stable_file(sparse_root / relative, MAX_TOTAL_BYTES)
        integrity_files.append(
            {"path": relative, "sha256": hashlib.sha256(payload).hexdigest()}
        )
    manifest["integrity"] = {"algorithm": "sha256", "files": integrity_files}
    return _serialize_json(manifest)


def build_manifest_updates(repository_root: Path) -> tuple[ManifestUpdate, ManifestUpdate]:
    """Calculate both manifest updates without mutating the repository."""

    root = repository_root.resolve(strict=True)
    _require_directory(root, "repository root")
    sparse_root = root / SPARSE_ROOT_RELATIVE
    _require_repository_path_ancestors(root, sparse_root, "sparse research root")
    _require_directory(sparse_root, "sparse research root")
    implementation_path = sparse_root / IMPLEMENTATION_MANIFEST_NAME
    corpus_path = sparse_root / CORPUS_MANIFEST_NAME
    implementation_bytes = _build_implementation_manifest(root)
    corpus_bytes = _build_corpus_manifest(root, implementation_bytes)
    return (
        ManifestUpdate(
            implementation_path,
            implementation_bytes,
            _read_stable_file(implementation_path, MANIFEST_BYTE_LIMIT),
        ),
        ManifestUpdate(
            corpus_path,
            corpus_bytes,
            _read_stable_file(corpus_path, MANIFEST_BYTE_LIMIT),
        ),
    )


def _atomic_write(path: Path, payload: bytes) -> None:
    """Atomically replace a manifest after durably writing a sibling temporary file."""

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def apply_manifest_updates(updates: Sequence[ManifestUpdate]) -> tuple[Path, ...]:
    """Write stale manifests in dependency order and return changed paths."""

    changed: list[Path] = []
    for update in updates:
        if update.is_current:
            continue
        _atomic_write(update.path, update.expected_bytes)
        changed.append(update.path)
    return tuple(changed)


def _parse_arguments(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail when either committed manifest is stale",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="atomically refresh stale committed manifests",
    )
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=Path(__file__).resolve().parents[4],
        help="repository root (defaults to the tool's checkout)",
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run the bounded manifest refresh command."""

    options = _parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        updates = build_manifest_updates(options.repository_root)
        stale = tuple(update for update in updates if not update.is_current)
        if options.check:
            if stale:
                for update in stale:
                    print(
                        f"stale sparse manifest: {update.path.relative_to(options.repository_root.resolve())}",
                        file=sys.stderr,
                    )
                print(
                    "Run refresh_sparse_manifests.py --write and review both manifests.",
                    file=sys.stderr,
                )
                return 1
            print("Sparse implementation and corpus integrity manifests are current.")
            return 0

        changed = apply_manifest_updates(updates)
        if changed:
            for path in changed:
                print(f"refreshed {path.relative_to(options.repository_root.resolve())}")
        else:
            print("Sparse implementation and corpus integrity manifests were already current.")
        return 0
    except (ManifestRefreshError, OSError) as error:
        print(f"manifest refresh failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
