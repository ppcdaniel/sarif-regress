#!/usr/bin/env python3
"""Safely extract the exactly pinned PMD distribution archive."""

from __future__ import annotations

import argparse
import shutil
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Final, Sequence


MAX_ARCHIVE_MEMBERS: Final = 20_000
MAX_EXPANDED_BYTES: Final = 512 * 1024 * 1024


class ArchiveError(RuntimeError):
    """Raised when an archive violates the capture extraction policy."""


def _validated_relative_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts:
        raise ArchiveError(f"Archive member {name!r} is not relative.")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ArchiveError(f"Archive member {name!r} contains unsafe segments.")
    return path


def _is_symbolic_link(member: zipfile.ZipInfo) -> bool:
    unix_mode = member.external_attr >> 16
    return stat.S_ISLNK(unix_mode)


def _has_unsupported_file_type(member: zipfile.ZipInfo) -> bool:
    if member.create_system != 3:
        return False
    unix_mode = member.external_attr >> 16
    file_type = stat.S_IFMT(unix_mode)
    expected_type = stat.S_IFDIR if member.is_dir() else stat.S_IFREG
    return file_type not in {0, expected_type}


# Time: O(M + B); Space: O(M), for M members and B expanded bytes.
def extract_zip(archive: Path, destination: Path, required_prefix: str) -> None:
    """Extract regular files below one required top-level prefix."""

    destination.mkdir(parents=True, exist_ok=False)
    resolved_destination = destination.resolve(strict=True)
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ArchiveError(
                f"Archive has {len(members)} members; maximum is "
                f"{MAX_ARCHIVE_MEMBERS}."
            )
        expanded_bytes = sum(member.file_size for member in members)
        if expanded_bytes > MAX_EXPANDED_BYTES:
            raise ArchiveError(
                f"Archive expands to {expanded_bytes} bytes; maximum is "
                f"{MAX_EXPANDED_BYTES}."
            )

        normalized_prefix = required_prefix.rstrip("/") + "/"
        observed_paths: set[PurePosixPath] = set()
        for member in members:
            if not member.filename.startswith(normalized_prefix):
                raise ArchiveError(
                    f"Archive member {member.filename!r} is outside "
                    f"{normalized_prefix!r}."
                )
            if _is_symbolic_link(member):
                raise ArchiveError(
                    f"Archive member {member.filename!r} is a symbolic link."
                )
            if _has_unsupported_file_type(member):
                raise ArchiveError(
                    f"Archive member {member.filename!r} has an unsupported "
                    "file type."
                )
            if (member.flag_bits & 0x1) != 0:
                raise ArchiveError(
                    f"Archive member {member.filename!r} is encrypted."
                )
            relative_path = _validated_relative_path(member.filename)
            if relative_path in observed_paths:
                raise ArchiveError(
                    f"Archive contains duplicate member {member.filename!r}."
                )
            observed_paths.add(relative_path)
            target = destination.joinpath(*relative_path.parts)
            try:
                target.resolve().relative_to(resolved_destination)
            except ValueError as error:
                raise ArchiveError(
                    f"Archive member {member.filename!r} escapes extraction."
                ) from error

            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with package.open(member, "r") as source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--required-prefix", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        extract_zip(
            parsed.archive.resolve(strict=True),
            parsed.destination.resolve(),
            parsed.required_prefix,
        )
    except (ArchiveError, OSError, zipfile.BadZipFile) as error:
        print(f"safe ZIP extraction failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
