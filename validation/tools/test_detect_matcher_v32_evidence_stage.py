#!/usr/bin/env python3
"""Behavioral tests for matcher-v3.2 evidence-stage selection."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from detect_matcher_v32_evidence_stage import detect_stage


HEAD = "a" * 40
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/holdout-validation.yml"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


class EvidenceStageTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write_erratum(self, status: str) -> None:
        write_json(
            self.root / "validation/holdout/interpretation-erratum.json",
            {
                "currentReportBinding": {
                    "matcherAlgorithmVersion": "sarifregress/matcher/v3.2",
                    "status": status,
                }
            },
        )

    def write_bound_inputs(
        self,
        *,
        byte_identity: bool,
        candidate: bool = True,
        workflow_conclusion: str | None = None,
        comparison_schema_version: str = "4",
        comparison_report_kind: str = "holdout-external-baseline-comparison",
    ) -> None:
        write_json(
            self.root / "validation/expected/comparison-summary.json",
            {
                "schemaVersion": comparison_schema_version,
                "reportKind": comparison_report_kind,
                "evaluation": {
                    "matcherAlgorithmVersion": "sarifregress/matcher/v3.2",
                },
                "releaseConditions": {
                    "crossPlatformByteIdentity": byte_identity,
                },
            },
        )
        linux_name, windows_name = (
            (
                f"holdout-v3.2-candidate-linux-{HEAD}",
                f"holdout-v3.2-candidate-windows-{HEAD}",
            )
            if candidate
            else ("holdout-linux", "holdout-windows")
        )
        write_json(
            self.root / "validation/holdout/cross-platform-attestation.json",
            {
                "schemaVersion": "4",
                "githubActions": {
                    "workflowHeadSha": HEAD,
                    "workflowConclusion": workflow_conclusion
                    or ("failure" if candidate else "success"),
                    "coordinatorJobConclusion": "success",
                    "coordinatorJobName": "Compare Linux and Windows normalized bytes",
                },
                "artifacts": {
                    "linux": {"name": linux_name},
                    "windows": {"name": windows_name},
                },
            },
        )

    def test_unbound_report_selects_stage_1_without_reading_legacy_outputs(self) -> None:
        self.write_erratum("candidate-unbound")
        self.assertEqual("stage1", detect_stage(self.root))

    def test_bound_unattested_comparison_selects_stage_2(self) -> None:
        self.write_erratum("bound")
        self.write_bound_inputs(byte_identity=False)
        self.assertEqual("stage2", detect_stage(self.root))

    def test_bound_attested_comparison_selects_normal(self) -> None:
        self.write_erratum("bound")
        self.write_bound_inputs(byte_identity=True)
        self.assertEqual("normal", detect_stage(self.root))

    def test_bound_comparison_requires_the_active_v4_envelope(self) -> None:
        self.write_erratum("bound")
        self.write_bound_inputs(
            byte_identity=False,
            comparison_schema_version="3",
        )
        with self.assertRaisesRegex(SystemExit, "wrong envelope"):
            detect_stage(self.root)

    def test_stage_2_rejects_normal_artifact_attestation(self) -> None:
        self.write_erratum("bound")
        self.write_bound_inputs(byte_identity=False, candidate=False)
        with self.assertRaisesRegex(SystemExit, "exact committed stage-1"):
            detect_stage(self.root)

    def test_candidate_attestation_must_record_failed_workflow(self) -> None:
        self.write_erratum("bound")
        self.write_bound_inputs(
            byte_identity=False,
            workflow_conclusion="success",
        )
        with self.assertRaisesRegex(SystemExit, "failed workflow"):
            detect_stage(self.root)

    def test_workflow_keeps_promotion_artifacts_fail_closed(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        bootstrap = workflow.split("\n  bootstrap-compare:\n", maxsplit=1)[1].split(
            "\n  bootstrap-refuse:\n", maxsplit=1
        )[0]
        bootstrap_needs = bootstrap.split("\n    steps:\n", maxsplit=1)[0]
        self.assertNotIn("\n      - sparse-experiment-compare\n", bootstrap_needs)
        sparse_upload = bootstrap.index(
            "- name: Upload bootstrap sparse release projection candidate"
        )
        stage1_upload = bootstrap.index(
            "- name: Upload byte-identical matcher-v3.2 candidate"
        )
        stage2_upload = bootstrap.index(
            "- name: Upload byte-identical matcher-v3.2 finalization candidate"
        )
        self.assertLess(sparse_upload, stage1_upload)
        self.assertLess(stage1_upload, stage2_upload)

        finalizer = bootstrap.split(
            "- name: Finalize authenticated matcher-v3.2 bound bytes", maxsplit=1
        )[1].split(
            "- name: Upload bootstrap sparse release projection candidate", maxsplit=1
        )[0]
        self.assertIn('"evaluation-metadata.json",', finalizer)

        normal = workflow.split("\n  compare:\n", maxsplit=1)[1]
        normal_needs = normal.split("\n    steps:\n", maxsplit=1)[0]
        self.assertIn("\n      - sparse-experiment-compare\n", normal_needs)


if __name__ == "__main__":
    unittest.main()
