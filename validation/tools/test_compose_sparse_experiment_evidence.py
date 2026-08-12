#!/usr/bin/env python3
"""Adversarial tests for offline sparse-experiment evidence composition."""

from __future__ import annotations

import copy
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from compose_sparse_experiment_evidence import (
    CompositionError,
    ROLE_CONFIG,
    _copy_bound_reference,
    authenticate_workflow,
    compose_evidence,
    load_bounded_json,
    verify_flat_checksum_manifest,
    write_json,
)


SOURCE_HEAD = "a" * 40
RUN_ID = 12345


class CompositeEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.metadata = self.root / "metadata"
        self.download = self.root / "download"
        self.metadata.mkdir()
        self.download.mkdir()
        self.run = {
            "id": RUN_ID,
            "status": "completed",
            "conclusion": "success",
            "path": ROLE_CONFIG["release"]["workflow"],
            "head_sha": SOURCE_HEAD,
            "repository": {"full_name": "ppcdaniel/sarif-regress"},
            "head_repository": {"full_name": "ppcdaniel/sarif-regress"},
        }
        self.artifacts = []
        for index, name in enumerate(ROLE_CONFIG["release"]["artifacts"]):
            (self.download / name).mkdir()
            self.artifacts.append(
                {
                    "id": 1000 + index,
                    "name": name,
                    "digest": f"sha256:{index + 1:x}" + "1" * 63,
                    "expired": False,
                    "workflow_run": {"id": RUN_ID, "head_sha": SOURCE_HEAD},
                }
            )
        self._write_metadata()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_metadata(self) -> None:
        write_json(self.metadata / "release-run.json", self.run)
        write_json(
            self.metadata / "release-artifacts.json",
            {"total_count": len(self.artifacts), "artifacts": self.artifacts},
        )

    def _authenticate(self) -> None:
        authenticate_workflow(
            role="release",
            expected_run_id=RUN_ID,
            expected_source_head=SOURCE_HEAD,
            run_metadata_path=self.metadata / "release-run.json",
            artifact_metadata_path=self.metadata / "release-artifacts.json",
            download_root=self.download,
        )

    @staticmethod
    def _write_flat_manifest(root: Path, manifest_name: str) -> None:
        files = sorted(path for path in root.iterdir() if path.name != manifest_name)
        manifest = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in files
        )
        (root / manifest_name).write_bytes(manifest.encode("ascii"))

    def _write_role_metadata(
        self,
        role: str,
        run_id: int,
        source_head: str,
        artifact_id_offset: int,
        download_root: Path,
    ) -> None:
        write_json(
            self.metadata / f"{role}-run.json",
            {
                "id": run_id,
                "status": "completed",
                "conclusion": "success",
                "path": ROLE_CONFIG[role]["workflow"],
                "head_sha": source_head,
                "repository": {"full_name": "ppcdaniel/sarif-regress"},
                "head_repository": {"full_name": "ppcdaniel/sarif-regress"},
            },
        )
        artifacts = []
        for index, name in enumerate(ROLE_CONFIG[role]["artifacts"]):
            artifacts.append(
                {
                    "id": artifact_id_offset + index,
                    "name": name,
                    "digest": f"sha256:{artifact_id_offset + index:064x}",
                    "expired": False,
                    "workflow_run": {"id": run_id, "head_sha": source_head},
                }
            )
            self.assertTrue((download_root / name).is_dir())
        write_json(
            self.metadata / f"{role}-artifacts.json",
            {"total_count": len(artifacts), "artifacts": artifacts},
        )

    def _prepare_complete_fixture(self) -> dict[str, object]:
        repository_root = Path(__file__).resolve().parents[2]
        expected = repository_root / "validation/research/sparse-sarif/expected"
        release_root = self.root / "release"
        determinism_root = self.root / "determinism"
        resources_root = self.root / "resources"
        for root in (release_root, determinism_root, resources_root):
            root.mkdir()

        release_projection = copy.deepcopy(
            load_bounded_json(
                expected / "projections/sparse-experiment-release-projection.json"
            )
        )
        assert isinstance(release_projection, dict)
        release_value = release_projection["variants"][0]["value"]
        assert isinstance(release_value, dict)
        projected_holdout = release_value["holdout"]
        assert isinstance(projected_holdout, dict)
        aggregate = projected_holdout["metrics"]
        assert isinstance(aggregate, dict)
        holdout = {
            "aggregate": {
                "labelledRelationships": projected_holdout["relationshipCount"],
                "labelledMatches": aggregate["acceptedPairs"],
                **aggregate,
                "ingestionFailures": projected_holdout["ingestionFailures"],
                "structuralFailures": projected_holdout["structuralFailures"],
            },
            "producers": [],
        }
        defect_fields = (
            "classificationMismatches",
            "incorrectNewClassifications",
            "incorrectResolvedClassifications",
            "unexpectedAmbiguityRefusals",
            "incorrectlyAutoMatchedAmbiguousCases",
            "ingestionFailures",
            "structuralFailures",
        )
        for producer in projected_holdout["byProducer"]:
            producer_metrics = producer["metrics"]
            holdout["producers"].append(
                {
                    "producerId": producer["producerFamily"],
                    "metrics": {
                        "labelledMatches": producer_metrics["acceptedPairs"],
                        **producer_metrics,
                        **{
                            field: (
                                producer["regressions"]
                                if field == "classificationMismatches"
                                else 0
                            )
                            for field in defect_fields
                        },
                    },
                }
            )
        development = {
            "passed": True,
            "failures": [],
            "aggregate": {"silentAmbiguousMatches": 0},
        }
        release_cross = release_root / "holdout-cross-platform"
        release_linux = release_root / "holdout-linux"
        release_windows = release_root / "holdout-windows"
        for root in (release_cross, release_linux, release_windows):
            root.mkdir()
            write_json(root / "sarif-regress-holdout.json", holdout)
            write_json(root / "development-corpus-report.json", development)
        holdout_digest = hashlib.sha256(
            (release_cross / "sarif-regress-holdout.json").read_bytes()
        ).hexdigest()
        development_digest = hashlib.sha256(
            (release_cross / "development-corpus-report.json").read_bytes()
        ).hexdigest()
        for variant in release_projection["variants"]:
            variant["value"]["holdout"].update(
                {
                    "reportPath": (
                        "expected/supporting/release/sarif-regress-holdout.json"
                    ),
                    "reportSha256": holdout_digest,
                }
            )
            variant["value"]["developmentCorpus"].update(
                {
                    "reportPath": (
                        "expected/supporting/release/development-corpus-report.json"
                    ),
                    "reportSha256": development_digest,
                }
            )
        write_json(
            release_cross / "sparse-experiment-release-composite-projection.json",
            release_projection,
        )
        for name in (
            "sparse-experiment-observations.json",
            "sparse-experiment-gate-evidence.json",
            "sparse-experiment-workflow-provenance.json",
        ):
            (release_cross / name).write_bytes((expected / name).read_bytes())
        self._write_flat_manifest(release_cross, "cross-platform-checksums.sha256")

        determinism_projection = copy.deepcopy(
            load_bounded_json(
                expected
                / "projections/sparse-experiment-determinism-projection.json"
            )
        )
        assert isinstance(determinism_projection, dict)
        determinism_cross = determinism_root / "cross-platform-determinism"
        determinism_cross.mkdir()
        gate_payload = (expected / "sparse-experiment-gate-evidence.json").read_bytes()
        observation_payload = (
            expected / "sparse-experiment-observations.json"
        ).read_bytes()
        semantic_values = copy.deepcopy(
            determinism_projection["variants"][0]["value"]
        )
        for name in ("linux", "windows", "comparison"):
            support_path = determinism_cross / f"sparse-experiment-determinism-{name}.json"
            write_json(support_path, semantic_values[name])
            reference = {
                "artifactPath": f"expected/supporting/determinism/{name}.json",
                "artifactSha256": hashlib.sha256(support_path.read_bytes()).hexdigest(),
            }
            for variant in determinism_projection["variants"]:
                variant["value"][name].update(reference)
        write_json(
            (
                determinism_cross
                / "sparse-experiment-determinism-composite-projection.json"
            ),
            determinism_projection,
        )
        for platform in ("linux", "windows"):
            platform_root = determinism_root / f"determinism-{platform}"
            for run_number in (1, 2):
                run_root = platform_root / "sparse-determinism" / f"run-{run_number}"
                (run_root / "observations").mkdir(parents=True)
                (run_root / "evaluation").mkdir()
                (run_root / "observations/sparse-experiment-observations.json").write_bytes(
                    observation_payload
                )
                (run_root / "evaluation/sparse-experiment-gate-evidence.json").write_bytes(
                    gate_payload
                )
            (
                determinism_cross
                / f"sparse-{platform}-sparse-experiment-observations.json"
            ).write_bytes(observation_payload)
            (
                determinism_cross
                / f"sparse-{platform}-sparse-experiment-gate-evidence.json"
            ).write_bytes(gate_payload)
        self._write_flat_manifest(determinism_cross, "checksums.sha256")

        resource_observations_path = (
            expected / "sparse-experiment-resource-observations.json"
        )
        resource_observations = load_bounded_json(resource_observations_path)
        assert isinstance(resource_observations, dict)
        resource_cells = []
        for observed in resource_observations["cells"]:
            operating_system = observed["operatingSystem"]
            finding_count = observed["findingCount"]
            dataset = observed["dataset"]
            platform = "linux" if operating_system == "ubuntu" else "windows"
            artifact_name = f"benchmark-{finding_count}-{dataset}-{platform}"
            artifact_root = resources_root / artifact_name
            artifact_root.mkdir()
            raw_payload = (
                f'{{"dataset":"{dataset}","findingCount":{finding_count}}}\n'
            ).encode("ascii")
            (artifact_root / "report.json").write_bytes(raw_payload)
            resource_cells.append(
                {
                    "operatingSystem": operating_system,
                    "findingCount": finding_count,
                    "dataset": dataset,
                    "candidateEdges": observed["candidateEdges"],
                    "maximumComponentSize": observed[
                        "maximumAdmittedAssignmentComponentSize"
                    ],
                    "elapsedMilliseconds": 1,
                    "peakWorkingSetBytes": 1,
                    "configuredCandidatePairLimit": observed[
                        "configuredCandidatePairLimit"
                    ],
                    "configuredAssignmentComponentLimit": observed[
                        "configuredAssignmentComponentLimit"
                    ],
                    "boundedRefusalObserved": observed["boundedRefusalObserved"],
                    "runtimeBudgetEnforced": observed["runtimeBudgetEnforced"],
                    "withinDocumentedLimits": observed["withinDocumentedLimits"],
                    "artifactPath": (
                        "expected/supporting/resources/"
                        f"{operating_system}-{finding_count}-{dataset}.json"
                    ),
                    "artifactSha256": hashlib.sha256(raw_payload).hexdigest(),
                }
            )
        resources_cross = resources_root / "benchmark-cross-platform"
        resources_cross.mkdir()
        resource_projection = load_bounded_json(
            expected / "projections/sparse-experiment-resource-projection.json"
        )
        assert isinstance(resource_projection, dict)
        full_resource_value = {
            "withinDocumentedLimits": True,
            "sourceContextProjectionBenchmarked": False,
            "cells": resource_cells,
            "evidencePath": "expected/sparse-experiment-resource-observations.json",
            "evidenceSha256": hashlib.sha256(
                resource_observations_path.read_bytes()
            ).hexdigest(),
        }
        full_resources = {
            "schemaVersion": "1",
            "kind": "sparse-experiment-resource-values/v1",
            "corpusManifestSha256": resource_projection["corpusManifestSha256"],
            "implementationManifestSha256": resource_projection[
                "implementationManifestSha256"
            ],
            "variants": [
                {"id": variant_id, "value": copy.deepcopy(full_resource_value)}
                for variant_id in (
                    "sarif-only-control",
                    "exact-region-snippet",
                    "token-window",
                    "relative-context",
                    "agreement-only-combination",
                )
            ],
        }
        write_json(
            resources_cross / "sparse-experiment-resource-values.json",
            full_resources,
        )
        write_json(
            resources_cross / "sparse-experiment-resource-projection.json",
            resource_projection,
        )
        (
            resources_cross / "sparse-experiment-resource-observations.json"
        ).write_bytes(resource_observations_path.read_bytes())
        self._write_flat_manifest(resources_cross, "checksums.sha256")

        self._write_role_metadata("release", 101, SOURCE_HEAD, 1_000, release_root)
        self._write_role_metadata(
            "determinism", 102, SOURCE_HEAD, 2_000, determinism_root
        )
        self._write_role_metadata("resources", 103, SOURCE_HEAD, 3_000, resources_root)
        return {
            "repository_root": repository_root,
            "metadata_root": self.metadata,
            "release_root": release_root,
            "determinism_root": determinism_root,
            "resources_root": resources_root,
            "release_run_id": 101,
            "determinism_run_id": 102,
            "resources_run_id": 103,
            "source_head_sha": SOURCE_HEAD,
        }

    def test_exact_successful_run_and_artifacts_are_admitted(self) -> None:
        self._authenticate()

    def test_workflow_path_prefix_is_not_an_exact_identity(self) -> None:
        self.run["path"] += "@refs/heads/main"
        self._write_metadata()
        with self.assertRaisesRegex(CompositionError, "exact successful run"):
            self._authenticate()

    def test_duplicate_json_properties_are_rejected_before_interpretation(self) -> None:
        path = self.metadata / "duplicate.json"
        path.write_text('{"id":1,"id":2}\n', encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(CompositionError, "Duplicate JSON property"):
            load_bounded_json(path)

    def test_non_utf8_json_is_rejected_before_interpretation(self) -> None:
        path = self.metadata / "non-utf8.json"
        path.write_bytes(b'{"value":"\xff"}\n')
        with self.assertRaisesRegex(CompositionError, "Evidence JSON is invalid"):
            load_bounded_json(path)

    def test_mixed_artifact_head_is_rejected(self) -> None:
        self.artifacts[-1]["workflow_run"]["head_sha"] = "b" * 40
        self._write_metadata()
        with self.assertRaisesRegex(CompositionError, "invalid provenance"):
            self._authenticate()

    def test_duplicate_artifact_id_is_rejected_across_names(self) -> None:
        self.artifacts[-1]["id"] = self.artifacts[0]["id"]
        self._write_metadata()
        with self.assertRaisesRegex(CompositionError, "repeats artifact ID"):
            self._authenticate()

    def test_zero_archive_digest_is_rejected(self) -> None:
        self.artifacts[0]["digest"] = "sha256:" + "0" * 64
        self._write_metadata()
        with self.assertRaisesRegex(CompositionError, "nonzero lowercase SHA-256"):
            self._authenticate()

    def test_raw_reference_hash_drift_is_rejected(self) -> None:
        raw = self.root / "raw.json"
        raw.write_text('{"value":1}\n', encoding="utf-8", newline="\n")
        stage_expected = self.root / "candidate" / "expected"
        stage_expected.mkdir(parents=True)
        with self.assertRaisesRegex(CompositionError, "Raw supporting reference mismatch"):
            _copy_bound_reference(
                raw,
                stage_expected,
                "expected/supporting/release/raw.json",
                "f" * 64,
            )

    def test_raw_reference_path_escape_is_rejected(self) -> None:
        raw = self.root / "raw.json"
        raw.write_text('{"value":1}\n', encoding="utf-8", newline="\n")
        stage_expected = self.root / "candidate" / "expected"
        stage_expected.mkdir(parents=True)
        with self.assertRaisesRegex(CompositionError, "canonical and contained"):
            _copy_bound_reference(
                raw,
                stage_expected,
                "expected/supporting/../escape.json",
                hashlib.sha256(raw.read_bytes()).hexdigest(),
            )

    def test_coordinator_manifest_must_enumerate_the_exact_artifact(self) -> None:
        coordinator = self.root / "coordinator"
        coordinator.mkdir()
        payload = b'{"value":1}\n'
        (coordinator / "bound.json").write_bytes(payload)
        (coordinator / "checksums.sha256").write_text(
            f"{hashlib.sha256(payload).hexdigest()}  bound.json\n",
            encoding="ascii",
            newline="\n",
        )
        (coordinator / "unbound.json").write_bytes(payload)
        with self.assertRaisesRegex(CompositionError, "exact artifact"):
            verify_flat_checksum_manifest(coordinator, "checksums.sha256")

    def test_complete_candidate_is_atomic_and_byte_deterministic(self) -> None:
        arguments = self._prepare_complete_fixture()
        first = self.root / "candidate-one"
        second = self.root / "candidate-two"
        compose_evidence(**arguments, output_root=first)
        compose_evidence(**arguments, output_root=second)

        def snapshot(root: Path) -> dict[str, bytes]:
            return {
                path.relative_to(root).as_posix(): path.read_bytes()
                for path in sorted(root.rglob("*"))
                if path.is_file()
            }

        self.assertEqual(snapshot(first), snapshot(second))
        self.assertTrue((first / "expected/experiment-report.json").is_file())
        self.assertFalse(
            (first / "expected/sparse-experiment-limitation.json").exists()
        )
        self.assertEqual(
            (self.metadata / "release-run.json").read_bytes(),
            (
                first
                / "expected/supporting/github/release-run.json"
            ).read_bytes(),
        )

        scanner_repository = self.root / "scanner-repository"
        scanner_research = (
            scanner_repository / "validation/research/sparse-sarif"
        )
        source_research = (
            arguments["repository_root"] / "validation/research/sparse-sarif"
        )
        archive = subprocess.run(
            ("git", "archive", "--format=tar", "HEAD"),
            cwd=arguments["repository_root"],
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        scanner_repository.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as stream:
            stream.extractall(scanner_repository, filter="data")
        shutil.rmtree(scanner_research / "expected")
        shutil.copytree(first / "expected", scanner_research / "expected")
        tools = source_research / "tools"
        sys.path.insert(0, str(tools))
        try:
            from scan_contamination import scan_research_root
        finally:
            sys.path.pop(0)
        findings = scan_research_root(scanner_research)
        self.assertEqual((), findings, "\n".join(finding.render() for finding in findings))

        occupied = self.root / "occupied-output"
        occupied.mkdir()
        sentinel = occupied / "sentinel.txt"
        sentinel.write_text("preserved\n", encoding="utf-8", newline="\n")
        with self.assertRaisesRegex(CompositionError, "must not already exist"):
            compose_evidence(**arguments, output_root=occupied)
        self.assertEqual(sentinel.read_bytes(), b"preserved\n")


if __name__ == "__main__":
    unittest.main()
