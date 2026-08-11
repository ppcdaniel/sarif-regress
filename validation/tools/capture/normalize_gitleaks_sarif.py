#!/usr/bin/env python3
"""Normalize only Gitleaks result ordering for reproducible projection.

Gitleaks 8.30.1 scans directory fragments concurrently and appends findings in
completion order.  The untouched producer capture is retained separately; this
adapter sorts the one SARIF run's complete result objects by canonical JSON and
does not change any result field.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Final, Sequence

from project_holdout import (
    MAX_JSON_BYTES,
    ProjectionError,
    _read_bounded_json,
    _write_atomic,
)


ALGORITHM_VERSION: Final = "gitleaks-result-order/v1"


class NormalizationError(RuntimeError):
    """Raised when a document is not the reviewed Gitleaks SARIF shape."""


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NormalizationError(f"{context} must be an object.")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise NormalizationError(f"{context} must be an array.")
    return value


def _result_sort_key(value: Any) -> str:
    _object(value, "runs[0].results item")
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def normalize_capture(input_path: Path, output_path: Path) -> None:
    """Write one ordering-only normalized copy of an authentic capture."""

    document = _object(_read_bounded_json(input_path), str(input_path))
    if document.get("version") != "2.1.0":
        raise NormalizationError("Gitleaks capture must declare SARIF 2.1.0.")
    runs = _array(document.get("runs"), "runs")
    if len(runs) != 1:
        raise NormalizationError("Gitleaks capture must contain exactly one run.")
    run = _object(runs[0], "runs[0]")
    tool = _object(run.get("tool"), "runs[0].tool")
    driver = _object(tool.get("driver"), "runs[0].tool.driver")
    if driver.get("name") != "gitleaks":
        raise NormalizationError(
            "Ordering normalization applies only to the Gitleaks producer."
        )
    results = _array(run.get("results"), "runs[0].results")
    run["results"] = sorted(results, key=_result_sort_key)

    payload = (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=1,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_JSON_BYTES:
        raise NormalizationError(
            f"Normalized capture exceeds the {MAX_JSON_BYTES}-byte bound."
        )
    output_parent = output_path.parent.resolve(strict=True)
    resolved_output = output_parent / output_path.name
    if resolved_output.exists() or resolved_output.is_symlink():
        raise NormalizationError(
            f"Normalization output already exists: {resolved_output}"
        )
    _write_atomic(resolved_output, payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Sort only Gitleaks SARIF results while retaining the untouched "
            "producer capture separately."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        normalize_capture(parsed.input, parsed.output)
    except (OSError, ProjectionError, NormalizationError) as error:
        print(f"Gitleaks normalization failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
