#!/usr/bin/env python3
"""Reproduce committed holdout projections from the committed raw SARIF."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Final, Sequence

from project_holdout import ProjectionError, project_case


PRODUCERS: Final = ("gitleaks", "pmd", "semgrep")
PROJECTED_FILES: Final = (
    "baseline.sarif",
    "candidate.sarif",
    "labels.json",
    "producer-input/projection-audit.json",
)
MAX_PROJECTED_BYTES: Final = 16 * 1024 * 1024


class VerificationError(RuntimeError):
    """Raised when the committed projection is not reproducible."""


def _read_regular_bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise VerificationError(f"{path} must be a regular non-symlink file.")
    with path.open("rb") as stream:
        payload = stream.read(MAX_PROJECTED_BYTES + 1)
    if len(payload) > MAX_PROJECTED_BYTES:
        raise VerificationError(
            f"{path} exceeds the {MAX_PROJECTED_BYTES}-byte projection bound."
        )
    return payload


def verify(repository_root: Path, output_root: Path) -> None:
    repository_root = repository_root.resolve(strict=True)
    output_parent = output_root.parent.resolve(strict=True)
    output_root = output_parent / output_root.name
    if output_root.exists() or output_root.is_symlink():
        raise VerificationError(
            f"Projection verification output already exists: {output_root}"
        )
    output_root.mkdir()

    cases_root = repository_root / "validation" / "holdout" / "cases"
    for producer in PRODUCERS:
        case_root = cases_root / producer
        generated_case_root = output_root / producer
        project_case(
            case_root.resolve(strict=True),
            (case_root / "producer-input" / "captures").resolve(strict=True),
            generated_case_root,
        )
        for relative_name in PROJECTED_FILES:
            committed = _read_regular_bounded(case_root / relative_name)
            generated = _read_regular_bounded(
                generated_case_root / relative_name
            )
            if committed != generated:
                raise VerificationError(
                    "Committed projection is not byte-reproducible: "
                    f"validation/holdout/cases/{producer}/{relative_name}"
                )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Regenerate all deterministic holdout projections from committed "
            "raw producer SARIF and compare exact bytes."
        )
    )
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        verify(parsed.repository_root, parsed.output_root)
    except (OSError, ProjectionError, VerificationError) as error:
        print(f"holdout projection verification failed: {error}", file=sys.stderr)
        return 1
    print(
        "Verified byte-reproducible raw-SARIF projections for "
        "gitleaks, pmd, and semgrep."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
