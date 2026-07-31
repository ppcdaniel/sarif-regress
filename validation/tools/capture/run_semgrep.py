#!/usr/bin/env python3
"""Start legacy Semgrep while isolating its native core libraries."""

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
    native_directory = libraries.parent
    core_loader = native_directory / "semgrep-core"
    native_core = native_directory / "semgrep-core.native"
    if core_loader.is_symlink() or not core_loader.is_file():
        raise RunnerError("Semgrep core loader must be a regular non-link file.")
    if native_core.is_symlink() or not native_core.is_file():
        raise RunnerError("Semgrep native core must be a regular non-link file.")
    command = list(arguments)
    if command[:1] == ["--"]:
        command.pop(0)
    if not command:
        raise RunnerError("Semgrep command arguments are required.")
    if command[:1] != ["--legacy"] or command.count("--legacy") != 1:
        raise RunnerError(
            "Semgrep command must explicitly select one --legacy mode."
        )

    # The documented legacy escape hatch keeps this Python process in charge.
    # The installed semgrep-core loader applies the wheel library directory to
    # each native core invocation without exporting it to this process or any
    # Python re-exec.
    environment_names = (
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "SEMGREP_SEND_METRICS",
        "SEMGREP_ENABLE_VERSION_CHECK",
        "SEMGREP_VERSION_CHECK_TIMEOUT",
        "SEMGREP_NEW_CLI_UX",
        "PATH",
    )
    previous_environment = {
        name: os.environ.get(name) for name in environment_names
    }
    previous_arguments = sys.argv
    try:
        # setup-python exports its own host library directory. Python has
        # already initialized by this point, so remove all loader overrides
        # before Semgrep can inherit them and restore them only for callers
        # that invoke run() in-process.
        os.environ.pop("LD_LIBRARY_PATH", None)
        os.environ.pop("LD_PRELOAD", None)
        os.environ["SEMGREP_SEND_METRICS"] = "off"
        os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        os.environ["SEMGREP_VERSION_CHECK_TIMEOUT"] = "0"
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
