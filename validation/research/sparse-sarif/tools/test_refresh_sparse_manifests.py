#!/usr/bin/env python3
"""Self-tests for deterministic sparse manifest refreshes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from refresh_sparse_manifests import (
    CORPUS_MANIFEST_NAME,
    IMPLEMENTATION_FILE_LIMIT,
    IMPLEMENTATION_MANIFEST_NAME,
    IMPLEMENTATION_RELATIVE_PATH_PATTERN,
    MAXIMUM_RELATIVE_PATH_CHARACTERS,
    ManifestRefreshError,
    SCANNER_RELATIVE_PATH,
    SPARSE_ROOT_RELATIVE,
    _require_valid_implementation_relative_path,
    apply_manifest_updates,
    build_manifest_updates,
)
from scan_contamination import (
    EXPERIMENT_IMPLEMENTATION_KIND,
    EXPERIMENT_IMPLEMENTATION_ROOT_FILES,
    EXPERIMENT_IMPLEMENTATION_ROOTS,
    POLICY_VERSION,
)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


class RefreshSparseManifestsTests(unittest.TestCase):
    """Exercise refresh ordering, coverage, determinism, and bounds."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repository_root = Path(self.temporary_directory.name)
        for relative in EXPERIMENT_IMPLEMENTATION_ROOT_FILES:
            path = self.repository_root / relative
            path.write_text(f"{relative}\n", encoding="utf-8", newline="\n")
        for index, relative_root in enumerate(EXPERIMENT_IMPLEMENTATION_ROOTS):
            root = self.repository_root / relative_root
            root.mkdir(parents=True)
            (root / f"Source{index}.cs").write_text(
                f"// source {index}\n",
                encoding="utf-8",
                newline="\n",
            )

        self.sparse_root = self.repository_root / SPARSE_ROOT_RELATIVE
        (self.sparse_root / "expected").mkdir(parents=True)
        (self.sparse_root / "expected/immutable.json").write_text(
            "{}\n", encoding="utf-8", newline="\n"
        )
        (self.sparse_root / "tools").mkdir()
        (self.sparse_root / SCANNER_RELATIVE_PATH).write_text(
            "POLICY = 1\n", encoding="utf-8", newline="\n"
        )
        _write_json(
            self.sparse_root / IMPLEMENTATION_MANIFEST_NAME,
            {
                "schemaVersion": "1",
                "kind": EXPERIMENT_IMPLEMENTATION_KIND,
                "algorithm": "sha256",
                "files": [{"path": "stale", "sha256": "0" * 64}],
            },
        )
        _write_json(
            self.sparse_root / CORPUS_MANIFEST_NAME,
            {
                "schemaVersion": "1",
                "families": [],
                "contamination": {
                    "scannerPath": SCANNER_RELATIVE_PATH,
                    "scannerSha256": "0" * 64,
                    "policyVersion": POLICY_VERSION,
                },
                "integrity": {"algorithm": "sha256", "files": []},
            },
        )

    def _replace_directory_with_link(self, directory: Path) -> None:
        """Move a directory outside the repository and replace it with a link."""

        external_directory = tempfile.TemporaryDirectory()
        self.addCleanup(external_directory.cleanup)
        target = Path(external_directory.name) / directory.name
        directory.rename(target)
        try:
            directory.symlink_to(target, target_is_directory=True)
            return
        except OSError as symlink_error:
            if os.name != "nt":
                self.skipTest(f"Directory links are unavailable: {symlink_error}")

        junction = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(directory), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if junction.returncode != 0:
            self.skipTest(
                "Directory links are unavailable: "
                + (junction.stderr.strip() or junction.stdout.strip())
            )

    def test_write_is_complete_deterministic_and_non_self_hashing(self) -> None:
        updates = build_manifest_updates(self.repository_root)
        changed = apply_manifest_updates(updates)
        self.assertEqual(
            [path.name for path in changed],
            [IMPLEMENTATION_MANIFEST_NAME, CORPUS_MANIFEST_NAME],
        )

        implementation_bytes = (self.sparse_root / IMPLEMENTATION_MANIFEST_NAME).read_bytes()
        implementation = json.loads(implementation_bytes)
        implementation_paths = [item["path"] for item in implementation["files"]]
        self.assertEqual(implementation_paths, sorted(implementation_paths))
        self.assertEqual(len(implementation_paths), len(set(implementation_paths)))

        corpus = json.loads((self.sparse_root / CORPUS_MANIFEST_NAME).read_bytes())
        integrity = corpus["integrity"]["files"]
        integrity_paths = [item["path"] for item in integrity]
        self.assertEqual(
            integrity_paths,
            [IMPLEMENTATION_MANIFEST_NAME, SCANNER_RELATIVE_PATH],
        )
        self.assertNotIn(CORPUS_MANIFEST_NAME, integrity_paths)
        self.assertFalse(any(path.startswith("expected/") for path in integrity_paths))
        scanner_record = next(
            item for item in integrity if item["path"] == SCANNER_RELATIVE_PATH
        )
        self.assertEqual(
            scanner_record["sha256"],
            corpus["contamination"]["scannerSha256"],
        )
        implementation_record = next(
            item for item in integrity if item["path"] == IMPLEMENTATION_MANIFEST_NAME
        )
        self.assertEqual(
            implementation_record["sha256"],
            hashlib.sha256(implementation_bytes).hexdigest(),
        )

        second_updates = build_manifest_updates(self.repository_root)
        self.assertTrue(all(update.is_current for update in second_updates))
        self.assertEqual(apply_manifest_updates(second_updates), ())

    def test_check_calculation_does_not_mutate_stale_manifests(self) -> None:
        implementation_path = self.sparse_root / IMPLEMENTATION_MANIFEST_NAME
        corpus_path = self.sparse_root / CORPUS_MANIFEST_NAME
        before = (implementation_path.read_bytes(), corpus_path.read_bytes())

        updates = build_manifest_updates(self.repository_root)

        self.assertTrue(any(not update.is_current for update in updates))
        self.assertEqual(before, (implementation_path.read_bytes(), corpus_path.read_bytes()))

    def test_implementation_hashes_use_canonical_lf_bytes(self) -> None:
        relative = EXPERIMENT_IMPLEMENTATION_ROOT_FILES[0]
        path = self.repository_root / relative
        canonical_payload = b"first\nsecond\n"
        path.write_bytes(b"first\r\nsecond\r\n")
        implementation_update, _ = build_manifest_updates(self.repository_root)
        implementation = json.loads(implementation_update.expected_bytes)
        record = next(item for item in implementation["files"] if item["path"] == relative)
        self.assertEqual(
            hashlib.sha256(canonical_payload).hexdigest(),
            record["sha256"],
        )

        without_terminal_lf = b"first\nsecond"
        path.write_bytes(without_terminal_lf)
        implementation_update, _ = build_manifest_updates(self.repository_root)
        implementation = json.loads(implementation_update.expected_bytes)
        record = next(item for item in implementation["files"] if item["path"] == relative)
        self.assertEqual(
            hashlib.sha256(without_terminal_lf).hexdigest(),
            record["sha256"],
        )
        self.assertNotEqual(
            hashlib.sha256(canonical_payload).hexdigest(),
            record["sha256"],
        )

        path.write_bytes(b"first\rsecond\n")
        with self.assertRaisesRegex(ManifestRefreshError, "lone carriage return"):
            build_manifest_updates(self.repository_root)

    def test_rejects_link_inside_implementation_root(self) -> None:
        target = self.repository_root / "target.cs"
        target.write_text("// target\n", encoding="utf-8", newline="\n")
        link = self.repository_root / EXPERIMENT_IMPLEMENTATION_ROOTS[0] / "linked.cs"
        try:
            link.symlink_to(target)
        except OSError as error:
            self.skipTest(f"Symbolic links are unavailable: {error}")

        with self.assertRaisesRegex(ManifestRefreshError, "links or special files"):
            build_manifest_updates(self.repository_root)

    def test_rejects_linked_implementation_root_ancestor(self) -> None:
        self._replace_directory_with_link(self.repository_root / "src")

        with self.assertRaisesRegex(
            ManifestRefreshError,
            "(?i)implementation root .* ancestor must be a non-link directory",
        ):
            build_manifest_updates(self.repository_root)

    def test_rejects_linked_sparse_root_ancestor(self) -> None:
        self._replace_directory_with_link(self.repository_root / "validation" / "research")

        with self.assertRaisesRegex(
            ManifestRefreshError,
            "(?i)sparse research root ancestor must be a non-link directory",
        ):
            build_manifest_updates(self.repository_root)

    def test_rejects_non_ascii_implementation_path(self) -> None:
        root = self.repository_root / EXPERIMENT_IMPLEMENTATION_ROOTS[0]
        (root / "nonportable-é.cs").write_text(
            "// invalid path\n", encoding="utf-8", newline="\n"
        )

        with self.assertRaisesRegex(ManifestRefreshError, "portable ASCII"):
            build_manifest_updates(self.repository_root)

    def test_implementation_path_length_matches_schema_boundary(self) -> None:
        prefix = "src/SarifRegress.Core/"
        suffix = ".cs"
        maximum_name_length = (
            MAXIMUM_RELATIVE_PATH_CHARACTERS - len(prefix) - len(suffix)
        )
        at_limit = prefix + ("a" * maximum_name_length) + suffix

        _require_valid_implementation_relative_path(at_limit)
        with self.assertRaisesRegex(ManifestRefreshError, "512-character"):
            _require_valid_implementation_relative_path(at_limit + "a")

    def test_implementation_path_contract_matches_schema(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "experiment-implementation-manifest.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        path_contract = schema["properties"]["files"]["items"]["properties"]["path"]

        self.assertEqual(
            IMPLEMENTATION_RELATIVE_PATH_PATTERN.pattern,
            path_contract["pattern"],
        )
        self.assertEqual(
            MAXIMUM_RELATIVE_PATH_CHARACTERS,
            path_contract["maxLength"],
        )

    def test_rejects_implementation_inventory_above_contract_bound(self) -> None:
        root = self.repository_root / EXPERIMENT_IMPLEMENTATION_ROOTS[0]
        existing_count = len(EXPERIMENT_IMPLEMENTATION_ROOT_FILES) + len(
            EXPERIMENT_IMPLEMENTATION_ROOTS
        )
        for index in range(IMPLEMENTATION_FILE_LIMIT - existing_count + 1):
            (root / f"Generated{index:03}.cs").write_text(
                "// bounded\n", encoding="utf-8", newline="\n"
            )

        with self.assertRaisesRegex(ManifestRefreshError, "256-file"):
            build_manifest_updates(self.repository_root)


if __name__ == "__main__":
    unittest.main()
