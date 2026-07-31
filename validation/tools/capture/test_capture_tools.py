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
from collections import Counter
from pathlib import Path

from extract_tar import ArchiveError as TarArchiveError
from extract_tar import extract_regular_member
from extract_zip import ArchiveError as ZipArchiveError
from extract_zip import extract_zip
from normalize_gitleaks_sarif import (
    NormalizationError,
    normalize_capture,
)
from project_holdout import MAX_JSON_DEPTH, ProjectionError, _read_bounded_json
from run_semgrep import RunnerError, run as run_semgrep
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

    def test_symbolic_link_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            link = root / "input.json"
            target.write_text("{}", encoding="utf-8")
            try:
                link.symlink_to(target)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaises(ProjectionError):
                _read_bounded_json(link)


class GitleaksNormalizationTests(unittest.TestCase):
    @staticmethod
    def _document(results: list[dict[str, object]]) -> dict[str, object]:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "gitleaks"}},
                    "results": results,
                }
            ],
        }

    def _normalize(self, document: dict[str, object]) -> bytes:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "producer.sarif"
            destination = root / "normalized.sarif"
            source.write_text(
                json.dumps(document, indent=1) + "\n",
                encoding="utf-8",
            )
            normalize_capture(source, destination)
            return destination.read_bytes()

    def test_permuted_results_normalize_to_identical_bytes(self) -> None:
        first = {"ruleId": "rule", "message": {"text": "first"}}
        second = {"ruleId": "rule", "message": {"text": "second"}}
        self.assertEqual(
            self._normalize(self._document([first, second])),
            self._normalize(self._document([second, first])),
        )

    def test_normalization_changes_only_order_and_keeps_source_bytes(self) -> None:
        repeated = {"ruleId": "rule", "message": {"text": "same"}}
        last = {"ruleId": "rule", "message": {"text": "last"}}
        document = self._document([last, repeated, repeated])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "producer.sarif"
            destination = root / "normalized.sarif"
            source_bytes = (json.dumps(document, indent=1) + "\n").encode(
                "utf-8"
            )
            source.write_bytes(source_bytes)
            normalize_capture(source, destination)
            self.assertEqual(source_bytes, source.read_bytes())

            normalized = json.loads(destination.read_text(encoding="utf-8"))
            original_results = document["runs"][0]["results"]
            normalized_results = normalized["runs"][0]["results"]
            self.assertEqual(len(original_results), len(normalized_results))
            canonical = lambda item: json.dumps(  # noqa: E731
                item,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            self.assertEqual(
                Counter(map(canonical, original_results)),
                Counter(map(canonical, normalized_results)),
            )
            document_without_results = json.loads(json.dumps(document))
            normalized_without_results = json.loads(json.dumps(normalized))
            document_without_results["runs"][0]["results"] = []
            normalized_without_results["runs"][0]["results"] = []
            self.assertEqual(
                document_without_results,
                normalized_without_results,
            )

    def test_rejects_non_gitleaks_document(self) -> None:
        document = self._document([])
        document["runs"][0]["tool"]["driver"]["name"] = "other"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "producer.sarif"
            source.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(NormalizationError):
                normalize_capture(source, root / "normalized.sarif")


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
    @staticmethod
    def _create_runner_fixture(root: Path) -> tuple[Path, Path, Path]:
        script = root / "semgrep"
        libraries = root / "native" / "libs"
        output = root / "observed.txt"
        libraries.mkdir(parents=True)
        for native_name in ("semgrep-core", "semgrep-core.native"):
            (libraries.parent / native_name).write_bytes(b"verified-native")
        script.write_text(
            "import os, pathlib, sys\n"
            "assert sys.argv[1] == '--legacy'\n"
            "pathlib.Path(sys.argv[2]).write_text("
            "str('LD_LIBRARY_PATH' in os.environ) + '\\n' + "
            "str('LD_PRELOAD' in os.environ) + '\\n' + "
            "os.environ['SEMGREP_SEND_METRICS'] + '\\n' + "
            "os.environ['SEMGREP_ENABLE_VERSION_CHECK'] + '\\n' + "
            "os.environ['SEMGREP_VERSION_CHECK_TIMEOUT'], encoding='utf-8')\n",
            encoding="utf-8",
        )
        return script, libraries, output

    def test_keeps_loader_variables_out_of_python_and_restores_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script, libraries, output = self._create_runner_fixture(root)
            names = (
                "LD_LIBRARY_PATH",
                "LD_PRELOAD",
                "SEMGREP_SEND_METRICS",
                "SEMGREP_ENABLE_VERSION_CHECK",
                "SEMGREP_VERSION_CHECK_TIMEOUT",
            )
            original = {name: os.environ.get(name) for name in names}
            for name in names:
                os.environ[name] = f"ambient-{name.lower()}"
            try:
                run_semgrep(
                    script,
                    libraries,
                    ["--", "--legacy", str(output)],
                )
                self.assertEqual(
                    "False\nFalse\noff\n0\n0",
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

    def test_requires_explicit_legacy_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script, libraries, output = self._create_runner_fixture(root)
            with self.assertRaises(RunnerError):
                run_semgrep(script, libraries, ["--", str(output)])


class CaptureProvenanceTests(unittest.TestCase):
    def test_mutated_required_provenance_is_rejected(self) -> None:
        source_root = Path(__file__).resolve().parents[3]
        relative_files = (
            "validation/holdout/manifest.json",
            "validation/holdout/cases/gitleaks/producer-input/captures/baseline.producer.sarif",
            "validation/holdout/cases/gitleaks/producer-input/captures/baseline.raw.sarif",
            "validation/holdout/cases/gitleaks/producer-input/captures/candidate.producer.sarif",
            "validation/holdout/cases/gitleaks/producer-input/captures/candidate.raw.sarif",
            "validation/tools/capture/capture-holdout.sh",
            "validation/tools/capture/normalize_gitleaks_sarif.py",
            "validation/tools/capture/project_holdout.py",
            "validation/tools/capture/verify_projected_holdout.py",
            "validation/tools/capture/verify_source_transformations.py",
            "validation/tools/capture/run_semgrep.py",
            "validation/tools/capture/semgrep-core-loader.sh",
            "validation/tools/capture/semgrep-requirements.linux-x86_64-py312.lock",
        )
        for mutation in (
            "help-hash",
            "reproduction-executable",
            "producer-capture",
        ):
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
                    elif mutation == "reproduction-executable":
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
                    else:
                        producer_capture = (
                            root
                            / "validation/holdout/cases/gitleaks/"
                            "producer-input/captures/baseline.producer.sarif"
                        )
                        producer_capture.write_bytes(
                            producer_capture.read_bytes() + b" "
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
