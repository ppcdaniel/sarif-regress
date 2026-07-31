#!/usr/bin/env python3
"""Start Semgrep without loading its bundled libraries into the Python host."""

from __future__ import annotations

import argparse
import os
import runpy
import sys
from pathlib import Path
from typing import Sequence


class RunnerError(RuntimeError):
    """Raised when the verified Semgrep runner inputs are unsafe."""


def run(
    semgrep_script: Path,
    library_directory: Path,
    arguments: Sequence[str],
) -> None:
    script = semgrep_script.resolve(strict=True)
    libraries = library_directory.resolve(strict=True)
    if semgrep_script.is_symlink() or not script.is_file():
        raise RunnerError("Semgrep console script must be a regular non-link file.")
    if library_directory.is_symlink() or not libraries.is_dir():
        raise RunnerError(
            "Semgrep library directory must be a regular non-link directory."
        )
    command = list(arguments)
    if command[:1] == ["--"]:
        command.pop(0)
    if not command:
        raise RunnerError("Semgrep command arguments are required.")

    # Python is already initialized with system libraries before this assignment.
    # Only Semgrep's subsequently exec'd native child sees the verified wheel
    # library directory, avoiding host-dependent libraries without preloading
    # the wheel's older libm into Python itself.
    environment_names = (
        "LD_LIBRARY_PATH",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "SEMGREP_VERSION_CHECK_TIMEOUT",
        "LD_PRELOAD",
    )
    previous_environment = {
        name: os.environ.get(name) for name in environment_names
    }
    previous_arguments = sys.argv
    try:
        os.environ["LD_LIBRARY_PATH"] = str(libraries)
        os.environ["SEMGREP_SEND_METRICS"] = "off"
        os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        os.environ["SEMGREP_VERSION_CHECK_TIMEOUT"] = "0"
        os.environ.pop("LD_PRELOAD", None)
        sys.argv = [str(script), *command]
        runpy.run_path(str(script), run_name="__main__")
    finally:
        sys.argv = previous_arguments
        for name, value in previous_environment.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--semgrep-script", type=Path, required=True)
    parser.add_argument("--library-directory", type=Path, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        run(
            parsed.semgrep_script,
            parsed.library_directory,
            parsed.arguments,
        )
    except (OSError, RunnerError) as error:
        print(f"Semgrep runner failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
