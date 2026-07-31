#!/usr/bin/env python3
"""Focused security and reproducibility tests for holdout capture helpers."""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from extract_tar import ArchiveError as TarArchiveError
from extract_tar import extract_regular_member
from extract_zip import ArchiveError as ZipArchiveError
from extract_zip import extract_zip
from project_holdout import MAX_JSON_DEPTH, ProjectionError, _read_bounded_json
from run_semgrep import run as run_semgrep
from verify_capture_provenance import ProvenanceError
from verify_capture_provenance import verify as verify_capture_provenance


class StrictJsonTests(unittest.TestCase):
    def _assert_rejected(self, payload: bytes) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(payload)
            with self.assertRaises(ProjectionError):
                _read_bounded_json(path)

    def test_duplicate_object_key_is_rejected(self) -> None:
        self._assert_rejected(b'{"a":1,"a":2}')

    def test_nonstandard_numeric_constant_is_rejected(self) -> None:
        self._assert_rejected(b'{"a":NaN}')

    def test_excessive_nesting_is_rejected(self) -> None:
        document: object = None
        for _ in range(MAX_JSON_DEPTH + 1):
            document = [document]
        self._assert_rejected(
            json.dumps(document, separators=(",", ":")).encode("utf-8")
        )


class TarExtractionTests(unittest.TestCase):
    @staticmethod
    def _write_member(
        package: tarfile.TarFile,
        name: str,
        payload: bytes,
    ) -> None:
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        member.mode = 0o755
        package.addfile(member, io.BytesIO(payload))

    def test_extracts_one_regular_member(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "tool.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                self._write_member(package, "gitleaks", b"verified-tool")
            destination = root / "out"
            extract_regular_member(archive, destination, "gitleaks")
            self.assertEqual(
                b"verified-tool",
                (destination / "gitleaks").read_bytes(),
            )

    def test_rejects_hard_link_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "tool.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                member = tarfile.TarInfo("gitleaks")
                member.type = tarfile.LNKTYPE
                member.linkname = "elsewhere"
                package.addfile(member)
            with self.assertRaises(TarArchiveError):
                extract_regular_member(archive, root / "out", "gitleaks")

    def test_rejects_duplicate_target_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "tool.tar.gz"
            with tarfile.open(archive, "w:gz") as package:
                self._write_member(package, "gitleaks", b"first")
                self._write_member(package, "gitleaks", b"second")
            with self.assertRaises(TarArchiveError):
                extract_regular_member(archive, root / "out", "gitleaks")


class ZipExtractionTests(unittest.TestCase):
    def test_rejects_unix_special_file_type(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "tool.zip"
            with zipfile.ZipFile(archive, "w") as package:
                member = zipfile.ZipInfo("pmd-bin-7.26.0/device")
                member.create_system = 3
                member.external_attr = (
                    stat.S_IFIFO | stat.S_IRUSR | stat.S_IWUSR
                ) << 16
                package.writestr(member, b"not-a-regular-file")
            with self.assertRaises(ZipArchiveError):
                extract_zip(archive, root / "out", "pmd-bin-7.26.0")


class SemgrepRunnerTests(unittest.TestCase):
    def test_sets_child_only_library_environment_and_restores_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "semgrep"
            libraries = root / "libs"
            output = root / "observed.txt"
            libraries.mkdir()
            script.write_text(
                "import os, pathlib, sys\n"
                "pathlib.Path(sys.argv[1]).write_text("
                "os.environ['LD_LIBRARY_PATH'] + '\\n' + "
                "os.environ['SEMGREP_SEND_METRICS'] + '\\n' + "
                "os.environ['SEMGREP_ENABLE_VERSION_CHECK'] + '\\n' + "
                "os.environ['SEMGREP_VERSION_CHECK_TIMEOUT'] + '\\n' + "
                "str('LD_PRELOAD' in os.environ), encoding='utf-8')\n",
                encoding="utf-8",
            )
            names = (
                "LD_LIBRARY_PATH",
                "SEMGREP_SEND_METRICS",
                "SEMGREP_ENABLE_VERSION_CHECK",
                "SEMGREP_VERSION_CHECK_TIMEOUT",
                "LD_PRELOAD",
            )
            original = {name: os.environ.get(name) for name in names}
            for name in names:
                os.environ[name] = f"ambient-{name.lower()}"
            os.environ["LD_PRELOAD"] = "ambient-preload"
            try:
                run_semgrep(script, libraries, ["--", str(output)])
                self.assertEqual(
                    f"{libraries.resolve()}\noff\n0\n0\nFalse",
                    output.read_text(encoding="utf-8"),
                )
            finally:
                for name, value in original.items():
                    if value is None:
                        os.environ.pop(name, None)
                    else:
                        os.environ[name] = value
            for name, value in original.items():
                self.assertEqual(value, os.environ.get(name))


class CaptureProvenanceTests(unittest.TestCase):
    def test_mutated_required_provenance_is_rejected(self) -> None:
        source_root = Path(__file__).resolve().parents[3]
        relative_files = (
            "validation/holdout/manifest.json",
            "validation/tools/capture/capture-holdout.sh",
            "validation/tools/capture/project_holdout.py",
            "validation/tools/capture/verify_projected_holdout.py",
            "validation/tools/capture/verify_source_transformations.py",
            "validation/tools/capture/run_semgrep.py",
            "validation/tools/capture/semgrep-requirements.linux-x86_64-py312.lock",
        )
        for mutation in ("help-hash", "reproduction-executable"):
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for relative in relative_files:
                        source = source_root / relative
                        destination = root / relative
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(source, destination)
                    provenance_source = (
                        source_root
                        / "validation/tools/capture/capture-provenance.json"
                    )
                    provenance = json.loads(
                        provenance_source.read_text(encoding="utf-8")
                    )
                    manifest_path = root / "validation/holdout/manifest.json"
                    if mutation == "help-hash":
                        semgrep = next(
                            item
                            for item in provenance["producers"]
                            if item["id"] == "semgrep"
                        )
                        semgrep["helpSha256"] = "0" * 64
                    else:
                        manifest = json.loads(
                            manifest_path.read_text(encoding="utf-8")
                        )
                        gitleaks = next(
                            item
                            for item in manifest["producers"]
                            if item["id"] == "gitleaks"
                        )
                        gitleaks["commands"]["reproduction"]["executable"] = (
                            "./wrong-script.sh"
                        )
                        manifest_path.write_text(
                            json.dumps(manifest, indent=2) + "\n",
                            encoding="utf-8",
                        )
                    destination = (
                        root / "validation/tools/capture/capture-provenance.json"
                    )
                    destination.write_text(
                        json.dumps(provenance, indent=2) + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(ProvenanceError):
                        verify_capture_provenance(root)


if __name__ == "__main__":
    unittest.main()
