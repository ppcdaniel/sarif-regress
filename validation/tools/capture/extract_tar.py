#!/usr/bin/env python3
"""Safely extract one executable from the pinned Gitleaks tar archive."""

from __future__ import annotations

import argparse
import shutil
import sys
import tarfile
from pathlib import Path
from typing import Final, Sequence


MAX_ARCHIVE_MEMBERS: Final = 128
MAX_MEMBER_BYTES: Final = 64 * 1024 * 1024


class ArchiveError(RuntimeError):
    """Raised when an archive violates the capture extraction policy."""


def extract_regular_member(
    archive: Path,
    destination: Path,
    member_name: str,
) -> None:
    """Extract exactly one uniquely named regular member without links."""

    if not member_name or "/" in member_name or "\\" in member_name:
        raise ArchiveError("The required member name must be one path segment.")
    destination.mkdir(parents=True, exist_ok=False)
    target = destination / member_name

    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ArchiveError(
                f"Archive has {len(members)} members; maximum is "
                f"{MAX_ARCHIVE_MEMBERS}."
            )
        selected = [member for member in members if member.name == member_name]
        if len(selected) != 1:
            raise ArchiveError(
                f"Archive must contain exactly one {member_name!r} member; "
                f"found {len(selected)}."
            )
        member = selected[0]
        if not member.isfile() or member.issym() or member.islnk():
            raise ArchiveError(
                f"Archive member {member_name!r} is not a regular non-link file."
            )
        if member.size <= 0 or member.size > MAX_MEMBER_BYTES:
            raise ArchiveError(
                f"Archive member {member_name!r} has disallowed size "
                f"{member.size}."
            )
        source = package.extractfile(member)
        if source is None:
            raise ArchiveError(
                f"Archive member {member_name!r} could not be opened."
            )
        with source, target.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        if target.stat().st_size != member.size:
            raise ArchiveError(
                f"Archive member {member_name!r} extraction size differs."
            )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--member", required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        extract_regular_member(
            parsed.archive.resolve(strict=True),
            parsed.destination.resolve(),
            parsed.member,
        )
    except (ArchiveError, OSError, tarfile.TarError) as error:
        print(f"safe TAR extraction failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
