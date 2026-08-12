#!/usr/bin/env python3
"""Create an ephemeral exact-head v3.2 evaluation identity for hosted bootstrap."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
from pathlib import Path


MATCHER_VERSION = "sarifregress/matcher/v3.2"
PRODUCT_VERSION_PATH = Path("src/SarifRegress.Core/ProductInformation.cs")
METADATA_PATH = Path("validation/holdout/evaluation-metadata.json")
SOURCE_PREFIX = b"sarifregress/source-tree/v1\0"
PRODUCT_VERSION_PATTERN = re.compile(
    rb'public const string Version = "([0-9A-Za-z.+-]+)";'
)


def run_git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def source_tree_hash(root: Path, source_sha: str) -> str:
    listing = run_git(
        root,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        source_sha,
        "--",
        "src",
    )
    entries: list[tuple[str, str]] = []
    for raw_record in listing.split(b"\0"):
        if not raw_record:
            continue
        header, separator, raw_path = raw_record.partition(b"\t")
        fields = header.split(b" ")
        if not separator or len(fields) != 3 or fields[1] != b"blob":
            raise SystemExit("Git returned an invalid tracked source entry.")
        path = raw_path.decode("utf-8", errors="strict")
        object_id = fields[2].decode("ascii", errors="strict").lower()
        if not path.startswith("src/") or "\\" in path or ".." in path.split("/"):
            raise SystemExit("Git returned a source path outside the tracked src tree.")
        if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id) is None:
            raise SystemExit("Git returned an invalid source blob identity.")
        entries.append((path, object_id))
    entries.sort(key=lambda item: item[0])
    if not entries or len({path for path, _ in entries}) != len(entries):
        raise SystemExit("The tracked source tree is empty or repeats a path.")

    digest = hashlib.sha256()
    digest.update(SOURCE_PREFIX)
    for path, object_id in entries:
        path_bytes = path.encode("utf-8")
        blob = run_git(root, "cat-file", "blob", object_id)
        digest.update(struct.pack(">I", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(struct.pack(">Q", len(blob)))
        digest.update(blob)
    return digest.hexdigest()


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"duplicate metadata property {name!r}")
        result[name] = value
    return result


def product_version(root: Path, source_sha: str) -> str:
    """Read the unique product version from the authenticated source commit."""

    payload = run_git(root, "show", f"{source_sha}:{PRODUCT_VERSION_PATH.as_posix()}")
    matches = PRODUCT_VERSION_PATTERN.findall(payload)
    if len(matches) != 1:
        raise SystemExit("The exact source commit has no unique product version constant.")
    return matches[0].decode("ascii", errors="strict")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    arguments = parser.parse_args()
    root = arguments.repository_root.resolve(strict=True)
    source_sha = arguments.source_sha
    if re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise SystemExit("--source-sha must be a lowercase full commit SHA.")
    if run_git(root, "rev-parse", "HEAD").decode("ascii").strip() != source_sha:
        raise SystemExit("The bootstrap checkout is not the requested exact head.")
    if run_git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise SystemExit("The bootstrap checkout must start clean.")

    metadata_path = root / METADATA_PATH
    if metadata_path.is_symlink() or not metadata_path.is_file():
        raise SystemExit("Evaluation metadata must be a regular tracked file.")
    with metadata_path.open("r", encoding="utf-8", newline="") as stream:
        metadata = json.load(stream, object_pairs_hook=reject_duplicate_pairs)
    metadata["repositoryCommitSha"] = source_sha
    metadata["sourceTreeSha256"] = source_tree_hash(root, source_sha)
    metadata["sarifRegressToolVersion"] = product_version(root, source_sha)
    metadata["matcherAlgorithmVersion"] = MATCHER_VERSION
    candidate = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    temporary = metadata_path.with_name(metadata_path.name + ".bootstrap")
    if temporary.exists() or temporary.is_symlink():
        raise SystemExit("The bootstrap metadata temporary path already exists.")
    try:
        temporary.write_bytes(candidate)
        os.replace(temporary, metadata_path)
    finally:
        if temporary.exists():
            temporary.unlink()

    changed = run_git(root, "diff", "--name-only").decode("utf-8").splitlines()
    if changed != [METADATA_PATH.as_posix()]:
        raise SystemExit("Bootstrap modified a path other than evaluation metadata.")
    if run_git(root, "diff", "--name-only", "--", "src"):
        raise SystemExit("Bootstrap modified product source.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
