#!/usr/bin/env python3
"""Tests for exact-commit matcher-v3.2 bootstrap metadata derivation."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bootstrap_matcher_v32_metadata import product_version


class BootstrapMatcherV32MetadataTests(unittest.TestCase):
    def test_product_version_is_read_from_the_exact_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            product_path = root / "src/SarifRegress.Core/ProductInformation.cs"
            product_path.parent.mkdir(parents=True)
            product_path.write_text(
                'public const string Version = "1.2.3-rc.4";\n',
                encoding="utf-8",
                newline="\n",
            )
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                check=True,
            )
            source_sha = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                stdout=subprocess.PIPE,
                text=True,
            ).stdout.strip()
            product_path.write_text(
                'public const string Version = "9.9.9";\n',
                encoding="utf-8",
                newline="\n",
            )

            self.assertEqual("1.2.3-rc.4", product_version(root, source_sha))

    def test_product_version_requires_one_exact_constant(self) -> None:
        with patch(
            "bootstrap_matcher_v32_metadata.run_git",
            return_value=b"public const string Name = \"sarif-regress\";\n",
        ):
            with self.assertRaisesRegex(SystemExit, "no unique product version"):
                product_version(Path("."), "a" * 40)


if __name__ == "__main__":
    unittest.main()
