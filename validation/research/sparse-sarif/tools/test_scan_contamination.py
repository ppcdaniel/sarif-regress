#!/usr/bin/env python3
"""Self-tests for the sparse-SARIF contamination policy."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scan_contamination import (
    EXPERIMENT_SCENARIO_IDS,
    EXPERIMENT_VARIANT_IDS,
    FAIL_CLOSED_SCENARIOS,
    FIXED_EXPERIMENT_GATES,
    RESOURCE_CELL_KEYS,
    Scanner,
    scan_research_root,
)


MESSAGE = "Avoid calling printStackTrace()."
REGION = {
    "startLine": 4,
    "startColumn": 9,
    "endLine": 4,
    "endColumn": 38,
}


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _selector(uri: str, *, line: int = 4) -> dict[str, object]:
    region = dict(REGION)
    region["startLine"] = line
    region["endLine"] = line
    return {
        "ruleId": "AvoidPrintStackTrace",
        "artifactUri": uri,
        "region": region,
        "message": MESSAGE,
    }


def _result(selector: dict[str, object]) -> dict[str, object]:
    return {
        "ruleId": selector["ruleId"],
        "message": {"text": selector["message"]},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": selector["artifactUri"]},
                    "region": selector["region"],
                }
            }
        ],
    }


def _sarif(results: list[dict[str, object]]) -> dict[str, object]:
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PMD",
                        "version": "7.26.0",
                    }
                },
                "results": results,
            }
        ],
    }


def _source() -> str:
    return (
        "package sample;\n"
        "final class Worker {\n"
        "    void report(Exception error) {\n"
        "        error.printStackTrace();\n"
        "    }\n"
        "}\n"
    )


def _gate_projection(**overrides: object) -> dict[str, object]:
    projection: dict[str, object] = {
        "pmdPrecision": 1.0,
        "pmdRecall": 1.0,
        "aggregatePrecision": 1.0,
        "aggregateRecall": 1.0,
        "silentlyMatchedAmbiguity": 0,
        "sourceSideLeakage": 0,
        "containmentRegressions": 0,
        "rootConfusions": 0,
        "unexplainedIngestionFailures": 0,
        "structuralFailures": 0,
        "developmentCorpusGreen": True,
        "semgrepNoRegression": True,
        "gitleaksNoRegression": True,
        "repeatedRunByteIdentical": True,
        "crossPlatformByteIdentical": True,
        "resourceBudgetsWithinLimits": True,
        "scenarioMatrixPassed": True,
        "corpusSpecificPreflightRequired": False,
    }
    projection.update(overrides)
    return projection


def _metrics(
    true_positives: int,
    false_positives: int,
    false_negatives: int,
) -> dict[str, object]:
    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 1.0
    )
    recall = (
        true_positives / (true_positives + false_negatives)
        if true_positives + false_negatives
        else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return {
        "truePositives": true_positives,
        "falsePositives": false_positives,
        "falseNegatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _experiment_variant(
    variant_id: str,
    **projection_overrides: object,
) -> dict[str, object]:
    projection = _gate_projection(**projection_overrides)
    scenarios = [
        {
            "scenarioId": scenario_id,
            "assertionsPassed": True,
            "preflightAccepted": scenario_id not in FAIL_CLOSED_SCENARIOS,
            "acceptedRelationships": 0,
            "baselineReadsFromCandidateRoot": 0,
            "candidateReadsFromBaselineRoot": 0,
            "containmentViolations": 0,
            "unexplainedIngestionFailures": 0,
            "structuralFailures": 0,
        }
        for scenario_id in EXPERIMENT_SCENARIO_IDS
    ]
    if projection["rootConfusions"]:
        scenarios[6]["preflightAccepted"] = True
        scenarios[6]["acceptedRelationships"] = projection["rootConfusions"]
        scenarios[6]["assertionsPassed"] = False
    if projection["sourceSideLeakage"]:
        scenarios[7]["candidateReadsFromBaselineRoot"] = projection[
            "sourceSideLeakage"
        ]
        scenarios[7]["assertionsPassed"] = False
    if projection["containmentRegressions"]:
        scenarios[5]["containmentViolations"] = projection[
            "containmentRegressions"
        ]
        scenarios[5]["assertionsPassed"] = False
    if projection["scenarioMatrixPassed"] is False and all(
        scenario["assertionsPassed"] is True for scenario in scenarios
    ):
        scenarios[0]["assertionsPassed"] = False
    no_hash_scenarios = json.loads(json.dumps(scenarios))
    if projection["corpusSpecificPreflightRequired"]:
        no_hash_scenarios[5]["assertionsPassed"] = False
        no_hash_scenarios[5]["preflightAccepted"] = True
        no_hash_scenarios[5]["acceptedRelationships"] = 1
    same_digest = "d" * 64
    linux_second_digest = (
        same_digest if projection["repeatedRunByteIdentical"] else "e" * 64
    )
    windows_digest = (
        same_digest if projection["crossPlatformByteIdentical"] else "f" * 64
    )
    resource_cells = []
    for operating_system, finding_count, dataset in RESOURCE_CELL_KEYS:
        resource_cells.append(
            {
                "operatingSystem": operating_system,
                "findingCount": finding_count,
                "dataset": dataset,
                "candidateEdges": finding_count if dataset == "unique" else 0,
                "maximumComponentSize": 1 if dataset == "unique" else 12,
                "elapsedMilliseconds": 100,
                "peakWorkingSetBytes": 16 * 1024 * 1024,
                "configuredCandidatePairLimit": 1_000_000,
                "configuredAssignmentComponentLimit": 12,
                "boundedRefusalObserved": dataset == "pathological",
                "runtimeBudgetEnforced": operating_system == "ubuntu",
                "withinDocumentedLimits": True,
            }
        )
    if projection["resourceBudgetsWithinLimits"] is False:
        resource_cells[0]["elapsedMilliseconds"] = 10_001
        resource_cells[0]["withinDocumentedLimits"] = False
    return {
        "id": variant_id,
        "description": f"Evidence variant {variant_id}.",
        "metrics": {
            "aggregate": _metrics(19, 0, 0),
            "byFamily": [
                {"familyId": "pmd-clean-a", **_metrics(8, 0, 0)},
                {"familyId": "pmd-clean-b", **_metrics(11, 0, 0)},
            ],
        },
        "gateProjection": projection,
        "releaseEvidence": {
            "holdout": {
                "relationshipCount": 75,
                "metrics": _metrics(75, 0, 0),
                "byProducer": [
                    {
                        "producerFamily": producer,
                        "metrics": _metrics(25, 0, 0),
                        "regressions": 0,
                    }
                    for producer in ("semgrep", "gitleaks", "pmd")
                ],
                "ingestionFailures": 0,
                "structuralFailures": 0,
            },
            "developmentCorpus": {
                "passed": projection["developmentCorpusGreen"],
                "regressions": 0,
                "silentlyMatchedAmbiguity": 0,
            },
        },
        "productionApplicability": {
            "trustedTreeHashPreflightEnabled": False,
            "scenariosWithoutTrustedTreeHashes": no_hash_scenarios,
            "metricsWithoutTrustedTreeHashes": _metrics(19, 0, 0),
            "corpusSpecificPreflightRequired": projection[
                "corpusSpecificPreflightRequired"
            ],
        },
        "scenarios": scenarios,
        "ambiguity": {
            "labelledUnits": 3,
            "correctRefusals": 3 - projection["silentlyMatchedAmbiguity"],
            "incorrectAutoMatches": projection["silentlyMatchedAmbiguity"],
        },
        "ingestion": {
            "casesEvaluated": 4,
            "failures": 0,
            "structuralFailures": 0,
        },
        "security": {
            "sourceSideLeakage": projection["sourceSideLeakage"],
            "containmentRegressions": projection["containmentRegressions"],
            "rootConfusions": projection["rootConfusions"],
        },
        "determinism": {
            "repeatedRunByteIdentical": projection["repeatedRunByteIdentical"],
            "linuxWindowsByteIdentical": projection["crossPlatformByteIdentical"],
            "linux": {
                "firstOutputSha256": same_digest,
                "secondOutputSha256": linux_second_digest,
            },
            "windows": {
                "firstOutputSha256": windows_digest,
                "secondOutputSha256": windows_digest,
            },
            "comparison": {
                "byteIdentical": projection["crossPlatformByteIdentical"],
            },
        },
        "resources": {
            "withinDocumentedLimits": projection["resourceBudgetsWithinLimits"],
            "cells": resource_cells,
        },
    }


def _experiment_report(
    variants: list[dict[str, object]],
    selected: str | None,
    decision: str,
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "corpusManifestSha256": "0" * 64,
        "implementation": {
            "name": "SarifRegress experiment harness",
            "version": "not-bound",
        },
        "fixedGates": dict(FIXED_EXPERIMENT_GATES),
        "variants": variants,
        "selectedVariant": selected,
        "decision": decision,
        "reasons": ["Synthetic scanner contract test."],
    }


def _complete_experiment_variants() -> list[dict[str, object]]:
    return [_experiment_variant(variant_id) for variant_id in EXPERIMENT_VARIANT_IDS]


def _proof(
    root: Path,
    baseline_path: str | None,
    candidate_path: str | None,
    description: str,
) -> dict[str, object]:
    proof: dict[str, object] = {
        "kind": "source-derived",
        "description": description,
    }
    if baseline_path is not None:
        proof["baselineSourcePath"] = baseline_path
        proof["baselineFileSha256"] = hashlib.sha256(
            (root / baseline_path).read_bytes()
        ).hexdigest()
    if candidate_path is not None:
        proof["candidateSourcePath"] = candidate_path
        proof["candidateFileSha256"] = hashlib.sha256(
            (root / candidate_path).read_bytes()
        ).hexdigest()
    return proof


def _tree_hash(root: Path, source_root: str) -> str:
    directory = root / source_root
    lines = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        relative = path.relative_to(directory).as_posix()
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}\n")
    return hashlib.sha256("".join(lines).encode("ascii")).hexdigest()


def _family(root: Path, family_id: str) -> dict[str, object]:
    family_root = f"cases/{family_id}"
    baseline_source = f"{family_root}/baseline/src/Worker.java"
    candidate_source = f"{family_root}/candidate/src/Worker.java"
    for relative in (baseline_source, candidate_source):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_source(), encoding="utf-8", newline="\n")

    baseline_sarif = f"{family_root}/baseline.sarif"
    candidate_sarif = f"{family_root}/candidate.sarif"
    shared = _selector("src/Worker.java")
    collision = _selector("src/Worker.java", line=8)
    ambiguity_baseline = _selector("src/Worker.java", line=12)
    ambiguity_candidate_first = _selector("src/Worker.java", line=16)
    ambiguity_candidate_second = _selector("src/Worker.java", line=12)
    _write_json(
        root / baseline_sarif,
        _sarif([_result(shared), _result(collision), _result(ambiguity_baseline)]),
    )
    _write_json(
        root / candidate_sarif,
        _sarif(
            [
                _result(shared),
                _result(collision),
                _result(ambiguity_candidate_second),
                _result(ambiguity_candidate_first),
            ]
        ),
    )
    labels_path = f"{family_root}/labels.json"
    labels = {
        "schemaVersion": "1",
        "familyId": family_id,
        "producerFamily": "pmd",
        "ruleId": "AvoidPrintStackTrace",
        "baselineSarif": "baseline.sarif",
        "candidateSarif": "candidate.sarif",
        "relationships": [
            {
                "id": f"{family_id}-relationship-main",
                "expectedClassification": "unchanged",
                "baseline": shared,
                "candidate": shared,
                "sourceTransformation": _proof(
                    root,
                    baseline_source,
                    candidate_source,
                    "The corresponding calls are unchanged in source.",
                ),
            }
        ],
        "new": [
            {
                "id": f"{family_id}-new-main",
                "expectedClassification": "new",
                "candidate": collision,
                "sourceTransformation": _proof(
                    root,
                    None,
                    candidate_source,
                    "A candidate-only call was introduced by the transformation.",
                ),
            }
        ],
        "resolved": [
            {
                "id": f"{family_id}-resolved-main",
                "expectedClassification": "resolved",
                "baseline": collision,
                "sourceTransformation": _proof(
                    root,
                    baseline_source,
                    None,
                    "A baseline-only call was removed by the transformation.",
                ),
            }
        ],
        "ambiguities": [
            {
                "id": f"{family_id}-ambiguity-main",
                "shape": "one-to-many",
                "baseline": [ambiguity_baseline],
                "candidate": [ambiguity_candidate_first, ambiguity_candidate_second],
                "expected": "refuse",
                "sourceTransformation": _proof(
                    root,
                    baseline_source,
                    candidate_source,
                    "Repeated equivalent calls intentionally remain ambiguous.",
                ),
            }
        ],
    }
    _write_json(root / labels_path, labels)
    ruleset_path = f"{family_root}/ruleset.xml"
    (root / ruleset_path).write_text(
        "<ruleset name=\"sparse\"><rule ref=\"category/java/errorprone.xml/AvoidPrintStackTrace\"/></ruleset>\n",
        encoding="utf-8",
        newline="\n",
    )
    return {
        "id": family_id,
        "labelsPath": labels_path,
        "rulesetPath": ruleset_path,
        "baseline": {
            "sourceRoot": f"{family_root}/baseline",
            "sarifPath": baseline_sarif,
            "sourceTreeSha256": "0" * 64,
            "rawCaptureSha256": "a" * 64,
            "projectedSarifSha256": "0" * 64,
            "resultCount": 2,
        },
        "candidate": {
            "sourceRoot": f"{family_root}/candidate",
            "sarifPath": candidate_sarif,
            "sourceTreeSha256": "0" * 64,
            "rawCaptureSha256": "b" * 64,
            "projectedSarifSha256": "0" * 64,
            "resultCount": 2,
        },
    }


def _create_fixture(root: Path) -> None:
    (root / "tools").mkdir(parents=True)
    (root / "tools/scan_contamination.py").write_text(
        "# fixture scanner provenance\n",
        encoding="utf-8",
        newline="\n",
    )
    manifest = {
        "schemaVersion": "1",
        "corpusId": "pmd-sparse-research",
        "producer": {
            "family": "pmd",
            "name": "PMD",
            "version": "7.26.0",
            "sourceCommit": "1" * 40,
            "license": {
                "identifier": "BSD-3-Clause",
                "name": "BSD 3-Clause License",
                "url": "https://github.com/pmd/pmd/blob/main/LICENSE",
            },
            "archive": {
                "url": "https://example.invalid/pmd.zip",
                "sizeBytes": 1,
                "sha256": "2" * 64,
            },
            "helpSha256": "3" * 64,
            "javaVersion": "17.0.19+10",
            "captureCommand": ["pmd", "check", "--format", "sarif"],
            "captureEnvironment": {
                "runnerImage": "ubuntu-24.04",
                "runnerVersion": "20260727.1",
                "os": "Ubuntu 24.04",
            },
        },
        "families": [
            _family(root, "pmd-clean-a"),
            _family(root, "pmd-clean-b"),
        ],
        "contamination": {
            "scannerPath": "tools/scan_contamination.py",
            "scannerSha256": "0" * 64,
            "policyVersion": "sparse-sarif-contamination/v1",
        },
        "integrity": {"algorithm": "sha256", "files": []},
    }
    _write_json(root / "manifest.json", manifest)
    _write_json(root / "expected/experiment.json", {"status": "not-run"})
    _refresh(root)


def _refresh(root: Path) -> None:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["contamination"]["scannerSha256"] = hashlib.sha256(
        (root / manifest["contamination"]["scannerPath"]).read_bytes()
    ).hexdigest()
    for family in manifest["families"]:
        labels_path = root / family["labelsPath"]
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        for collection in ("relationships", "new", "resolved", "ambiguities"):
            for entry in labels[collection]:
                proof = entry["sourceTransformation"]
                for side in ("baseline", "candidate"):
                    path_key = f"{side}SourcePath"
                    hash_key = f"{side}FileSha256"
                    if path_key in proof:
                        proof[hash_key] = hashlib.sha256(
                            (root / proof[path_key]).read_bytes()
                        ).hexdigest()
        _write_json(labels_path, labels)
        for side_name in ("baseline", "candidate"):
            side = family[side_name]
            side["sourceTreeSha256"] = _tree_hash(root, side["sourceRoot"])
            sarif_path = root / side["sarifPath"]
            side["projectedSarifSha256"] = hashlib.sha256(
                sarif_path.read_bytes()
            ).hexdigest()
            document = json.loads(sarif_path.read_text(encoding="utf-8"))
            side["resultCount"] = sum(
                len(run.get("results", [])) for run in document.get("runs", [])
            )
    manifest["integrity"]["files"] = []
    integrity_paths = sorted(
        (
            path.relative_to(root).as_posix(),
            path,
        )
        for path in root.rglob("*")
        if path != manifest_path
        and not path.is_symlink()
        and path.is_file()
        and path.relative_to(root).parts[0] != "expected"
    )
    for relative, path in integrity_paths:
        manifest["integrity"]["files"].append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    _write_json(manifest_path, manifest)
    manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    expected_root = root / "expected"
    if expected_root.exists():
        for path in expected_root.rglob("*.json"):
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(document, dict)
                and {"fixedGates", "variants", "selectedVariant", "decision"}
                <= set(document)
            ):
                document["corpusManifestSha256"] = manifest_sha256
                _write_json(path, document)
        expected_files = sorted(
            (
                path
                for path in expected_root.rglob("*")
                if path.is_file()
                and not path.is_symlink()
                and path.name != "checksums.sha256"
            ),
            key=lambda path: path.relative_to(expected_root).as_posix(),
        )
        checksum_text = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(expected_root).as_posix()}\n"
            for path in expected_files
        )
        (expected_root / "checksums.sha256").write_text(
            checksum_text,
            encoding="ascii",
            newline="\n",
        )


def _codes(root: Path) -> set[str]:
    return {finding.code for finding in scan_research_root(root)}


class ContaminationScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        _create_fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_clean_fixture_passes(self) -> None:
        self.assertEqual((), scan_research_root(self.root))

    def test_label_id_and_distinctive_proof_phrase_are_rejected(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source()
            + "// pmd-clean-a-relationship-main\n"
            + "// The corresponding calls are unchanged in source.\n",
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        self.assertIn("SOURCE002", _codes(self.root))

    def test_known_marker_and_suspicious_identifier_are_rejected(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "final class Worker",
                "final class Worker { int caseId001; // HOLDOUT",
            ),
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("SOURCE003", codes)
        self.assertIn("SOURCE004", codes)

    def test_correspondence_comment_adjacent_to_call_is_rejected(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "        error.printStackTrace();",
                "        // same finding as candidate\n        error.printStackTrace();",
            ),
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        self.assertIn("SOURCE005", _codes(self.root))

    def test_symlink_and_nonregular_file_are_rejected(self) -> None:
        link = self.root / "cases/pmd-clean-a/baseline/src/Alias.java"
        try:
            link.symlink_to("Worker.java")
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        self.assertIn("FS004", _codes(self.root))

        mkfifo = getattr(os, "mkfifo", None)
        if mkfifo is None:
            return
        fifo = self.root / "cases/pmd-clean-a/baseline/src/pipe"
        try:
            mkfifo(fifo)
        except OSError as error:
            self.skipTest(f"FIFOs unavailable: {error}")
        codes = _codes(self.root)
        self.assertIn("FS005", codes)

    def test_environmental_json_is_rejected(self) -> None:
        _write_json(
            self.root / "expected/environment.json",
            {
                "path": "/home/runner/work/capture.sarif",
                "generatedAt": "2026-08-02T03:04:05Z",
                "hostname": "fv-az123",
            },
        )
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertTrue({"AMBIENT001", "AMBIENT002", "AMBIENT003"} <= codes)

    def test_expected_output_checksum_mismatch_is_rejected(self) -> None:
        checksum = self.root / "expected/checksums.sha256"
        lines = checksum.read_text(encoding="ascii").splitlines()
        _, name = lines[0].split("  ", maxsplit=1)
        checksum.write_text(
            f"{'0' * 64}  {name}\n",
            encoding="ascii",
            newline="\n",
        )
        self.assertIn("EXPECTED008", _codes(self.root))

    def test_sparse_capture_rejects_fingerprints_and_snippets(self) -> None:
        path = self.root / "cases/pmd-clean-a/baseline.sarif"
        document = json.loads(path.read_text(encoding="utf-8"))
        result = document["runs"][0]["results"][0]
        result["partialFingerprints"] = {"primaryLocationLineHash": "abc"}
        result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": "error.printStackTrace();"
        }
        _write_json(path, document)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("SPARSE001", codes)
        self.assertIn("SPARSE002", codes)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        path = self.root / "expected/duplicate.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'{"value":1,"value":2}\n')
        _refresh(self.root)
        self.assertIn("JSON002", _codes(self.root))

    def test_invalid_utf8_crlf_and_bom_are_rejected(self) -> None:
        paths = {
            "invalid.json": b'{"value":"\xff"}\n',
            "crlf.json": b'{"value":1}\r\n',
            "bom.json": b'\xef\xbb\xbf{"value":1}\n',
        }
        expected = {"TEXT004", "TEXT002", "TEXT001"}
        directory = self.root / "expected"
        directory.mkdir(parents=True, exist_ok=True)
        for name, payload in paths.items():
            (directory / name).write_bytes(payload)
        _refresh(self.root)
        self.assertTrue(expected <= _codes(self.root))

    def test_result_index_ground_truth_is_rejected(self) -> None:
        path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(path.read_text(encoding="utf-8"))
        labels["relationships"][0]["baselineResultIndex"] = 0
        _write_json(path, labels)
        _refresh(self.root)
        self.assertIn("LABEL007", _codes(self.root))

    def test_exact_selector_order_leakage_is_rejected(self) -> None:
        self._add_ordered_relationship(
            baseline_uri="src/Zulu.java",
            candidate_uri="src/Zulu.java",
        )
        codes = _codes(self.root)
        self.assertIn("ORDER001", codes)
        self.assertIn("ORDER003", codes)

    def test_aligned_unique_basename_order_leakage_is_rejected(self) -> None:
        self._add_ordered_relationship(
            baseline_uri="src/Zulu.java",
            candidate_uri="moved/Zulu.java",
        )
        self.assertIn("ORDER002", _codes(self.root))

    def test_relationship_order_leakage_is_label_array_order_invariant(self) -> None:
        self._add_ordered_relationship(
            baseline_uri="src/Zulu.java",
            candidate_uri="src/Zulu.java",
        )
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["relationships"].reverse()
        _write_json(labels_path, labels)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("ORDER001", codes)
        self.assertIn("ORDER003", codes)

    def test_reverse_relationship_mapping_order_leakage_is_rejected(self) -> None:
        self._add_ordered_relationship(
            baseline_uri="src/Zulu.java",
            candidate_uri="src/Zulu.java",
        )
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        first = labels["relationships"][0]
        second = labels["relationships"][1]
        first["candidate"], second["candidate"] = (
            second["candidate"],
            first["candidate"],
        )
        labels["relationships"].reverse()
        _write_json(labels_path, labels)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("ORDER001", codes)
        self.assertIn("ORDER003", codes)

    def test_diagnostics_are_stably_ordered(self) -> None:
        path = self.root / "expected/environment.json"
        _write_json(
            path,
            {
                "hostname": "localhost",
                "path": "C:\\checkout\\report.json",
            },
        )
        _refresh(self.root)
        first = scan_research_root(self.root)
        second = scan_research_root(self.root)
        self.assertEqual(first, second)
        self.assertEqual(tuple(sorted(first)), first)

    def test_separator_normalized_label_id_identifier_is_rejected(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "final class Worker {",
                "final class Worker {\n    int pmd_clean_a_relationship_main;",
            ),
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        self.assertIn("SOURCE002", _codes(self.root))

    def test_separator_normalized_label_id_comment_is_rejected(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "        error.printStackTrace();",
                "        // pmd clean a relationship main\n"
                "        error.printStackTrace();",
            ),
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        self.assertIn("SOURCE002", _codes(self.root))

    def test_short_label_id_in_sarif_is_rejected_at_token_boundaries(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["relationships"][0]["id"] = "abc"
        _write_json(labels_path, labels)
        sarif_path = self.root / "cases/pmd-clean-a/baseline.sarif"
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        sarif["runs"][0]["properties"] = {"note": "abc"}
        _write_json(sarif_path, sarif)
        _refresh(self.root)
        self.assertIn("SARIF008", _codes(self.root))

    def test_natural_identity_and_matches_comments_are_allowed(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "        error.printStackTrace();",
                "        // Identity management is enabled.\n"
                "        // Matches the retry policy.\n"
                "        error.printStackTrace();",
            ),
            encoding="utf-8",
            newline="\n",
        )
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertNotIn("SOURCE003", codes)
        self.assertNotIn("SOURCE005", codes)

    def test_deep_json_is_rejected_before_materialization(self) -> None:
        deep = self.root / "expected/deep.json"
        deep.write_text("[" * 10_000 + "0" + "]" * 10_000 + "\n", encoding="ascii")
        self.assertIn("LIMIT005", _codes(self.root))

    def test_aggregate_byte_limit_stops_file_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_bytes(b"a" * 4)
            (root / "b.txt").write_bytes(b"b" * 4)
            (root / "c.txt").write_bytes(b"c" * 4)
            scanner = Scanner(root)
            with patch("scan_contamination.MAX_TOTAL_BYTES", 5):
                scanner._enumerate_tree()
            self.assertEqual(["a.txt"], sorted(scanner.files))
            self.assertIn("LIMIT002", {finding.code for finding in scanner.findings})

    def test_aggregate_read_limit_rejects_post_enumeration_growth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "value.txt"
            path.write_bytes(b"ok")
            scanner = Scanner(root)
            with patch("scan_contamination.MAX_TOTAL_BYTES", 5):
                scanner._enumerate_tree()
                path.write_bytes(b"expanded")
                self.assertIsNone(scanner._read("value.txt"))
            self.assertIn("LIMIT002", {finding.code for finding in scanner.findings})

    def test_directory_count_and_depth_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a/b/c").mkdir(parents=True)
            count_scanner = Scanner(root)
            with patch("scan_contamination.MAX_DIRECTORIES", 2):
                count_scanner._enumerate_tree()
            self.assertIn(
                "LIMIT009",
                {finding.code for finding in count_scanner.findings},
            )
            depth_scanner = Scanner(root)
            with patch("scan_contamination.MAX_DIRECTORY_DEPTH", 1):
                depth_scanner._enumerate_tree()
            self.assertIn(
                "LIMIT008",
                {finding.code for finding in depth_scanner.findings},
            )

    def test_single_directory_entry_materialization_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a.txt", "b.txt", "c.txt"):
                (root / name).write_text(name, encoding="utf-8")
            scanner = Scanner(root)
            with patch("scan_contamination.MAX_DIRECTORY_ENTRIES", 2):
                scanner._enumerate_tree()
            self.assertEqual({}, scanner.files)
            self.assertIn("LIMIT010", {item.code for item in scanner.findings})

    def test_reparse_attribute_is_rejected(self) -> None:
        scanner = Scanner(self.root)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        status = SimpleNamespace(st_file_attributes=reparse)
        self.assertTrue(scanner._is_reparse_point(status, "junction"))  # type: ignore[arg-type]

    def test_windows_reparse_check_fails_closed_without_attributes(self) -> None:
        scanner = Scanner(self.root)
        with patch("scan_contamination.os.name", "nt"):
            self.assertTrue(
                scanner._is_reparse_point(SimpleNamespace(), "unknown")  # type: ignore[arg-type]
            )
        self.assertIn("FS009", {finding.code for finding in scanner.findings})

    @unittest.skipUnless(os.name == "nt", "Windows junction test")
    def test_windows_junction_is_rejected(self) -> None:
        target = self.root / "junction-target"
        target.mkdir()
        junction = self.root / "junction"
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            self.skipTest(f"junction creation unavailable: {completed.stderr}")
        try:
            self.assertIn("FS004", _codes(self.root))
        finally:
            os.rmdir(junction)

    @unittest.skipIf(os.name == "nt", "POSIX no-follow traversal test")
    def test_parent_swap_cannot_redirect_a_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe").mkdir()
            (root / "safe/value.txt").write_text("safe", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (outside / "value.txt").write_text("unsafe", encoding="utf-8")
            scanner = Scanner(root)
            scanner._enumerate_tree()
            (root / "safe").rename(root / "original")
            try:
                (root / "safe").symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            self.assertIsNone(scanner._read("safe/value.txt"))
            self.assertIn("FS008", {finding.code for finding in scanner.findings})

    @unittest.skipIf(os.name == "nt", "POSIX anchored enumeration race test")
    def test_parent_swap_during_enumeration_cannot_admit_outside_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory)
            root = container / "root"
            outside = container / "outside"
            (root / "safe").mkdir(parents=True)
            outside.mkdir()
            (root / "safe/inside.txt").write_text("inside", encoding="utf-8")
            (root / "trigger.txt").write_text("trigger", encoding="utf-8")
            (outside / "secret.txt").write_text("outside", encoding="utf-8")
            original_bounded = Scanner._bounded_entries
            swapped = False

            class SwappingEntry:
                def __init__(self, entry: os.DirEntry[str]) -> None:
                    self._entry = entry

                @property
                def name(self) -> str:
                    return self._entry.name

                def stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
                    nonlocal swapped
                    if self.name == "trigger.txt" and not swapped:
                        (root / "safe").rename(root / "original")
                        (root / "safe").symlink_to(outside, target_is_directory=True)
                        swapped = True
                    return self._entry.stat(follow_symlinks=follow_symlinks)

                def __getattr__(self, name: str) -> object:
                    return getattr(self._entry, name)

            def swapping_entries(
                scanner: Scanner,
                target: int | Path,
                relative: str,
            ) -> list[os.DirEntry[str]] | None:
                entries = original_bounded(scanner, target, relative)
                if entries is None or relative != ".":
                    return entries
                return [SwappingEntry(entry) for entry in entries]  # type: ignore[list-item]

            scanner = Scanner(root)
            with patch.object(Scanner, "_bounded_entries", swapping_entries):
                scanner._enumerate_tree()
            self.assertTrue(swapped)
            self.assertIn("safe/inside.txt", scanner.files)
            self.assertNotIn("safe/secret.txt", scanner.files)
            self.assertIsNone(scanner._read("safe/inside.txt"))

    def test_label_selector_must_resolve_uniquely(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["relationships"][0]["baseline"]["region"]["startLine"] = 999
        labels["relationships"][0]["baseline"]["region"]["endLine"] = 999
        _write_json(labels_path, labels)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("LABEL012", codes)
        self.assertIn("LABEL014", codes)

    def test_duplicate_label_endpoint_is_rejected(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        duplicate = json.loads(json.dumps(labels["relationships"][0]))
        duplicate["id"] = "pmd-clean-a-relationship-duplicate"
        labels["relationships"].append(duplicate)
        _write_json(labels_path, labels)
        _refresh(self.root)
        self.assertIn("LABEL013", _codes(self.root))

    def test_unassigned_sarif_result_is_rejected(self) -> None:
        path = self.root / "cases/pmd-clean-a/baseline.sarif"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["runs"][0]["results"].append(
            _result(_selector("src/Worker.java", line=20))
        )
        _write_json(path, document)
        _refresh(self.root)
        self.assertIn("LABEL014", _codes(self.root))

    def test_duplicate_sarif_selector_is_rejected(self) -> None:
        path = self.root / "cases/pmd-clean-a/baseline.sarif"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["runs"][0]["results"].append(document["runs"][0]["results"][0])
        _write_json(path, document)
        _refresh(self.root)
        self.assertIn("LABEL012", _codes(self.root))

    def test_ambiguity_shape_cardinality_is_enforced(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["ambiguities"][0]["shape"] = "many-to-one"
        _write_json(labels_path, labels)
        _refresh(self.root)
        self.assertIn("LABEL015", _codes(self.root))

    def test_inverted_label_and_sarif_regions_are_rejected(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["relationships"][0]["baseline"]["region"]["endLine"] = 3
        _write_json(labels_path, labels)
        sarif_path = self.root / "cases/pmd-clean-b/baseline.sarif"
        sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]["endLine"] = 3
        _write_json(sarif_path, sarif)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("LABEL011", codes)
        self.assertIn("SARIF006", codes)

    def test_noncanonical_selector_uri_aliases_are_rejected(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        sarif_path = self.root / "cases/pmd-clean-a/baseline.sarif"
        original_labels = json.loads(labels_path.read_text(encoding="utf-8"))
        original_sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
        for alias in (
            "src/./Worker.java",
            "src//Worker.java",
            "src/Worker.java/",
            "src/%2e%2e/Worker.java",
            "a" * 513,
        ):
            with self.subTest(alias=alias):
                labels = json.loads(json.dumps(original_labels))
                labels["relationships"][0]["baseline"]["artifactUri"] = alias
                _write_json(labels_path, labels)
                sarif = json.loads(json.dumps(original_sarif))
                sarif["runs"][0]["results"][0]["locations"][0][
                    "physicalLocation"
                ]["artifactLocation"]["uri"] = alias
                _write_json(sarif_path, sarif)
                _refresh(self.root)
                codes = _codes(self.root)
                self.assertIn("LABEL018", codes)
                self.assertIn("SARIF006", codes)
        _write_json(labels_path, original_labels)
        _write_json(sarif_path, original_sarif)
        _refresh(self.root)

    def test_false_source_transformation_hash_is_rejected(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["relationships"][0]["sourceTransformation"][
            "baselineFileSha256"
        ] = "0" * 64
        _write_json(labels_path, labels)
        manifest_path = self.root / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["integrity"]["files"]:
            if entry["path"] == "cases/pmd-clean-a/labels.json":
                entry["sha256"] = hashlib.sha256(labels_path.read_bytes()).hexdigest()
        _write_json(manifest_path, manifest)
        self.assertIn("LABEL017", _codes(self.root))

    def test_source_transformation_path_cannot_cross_side_roots(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        proof = labels["relationships"][0]["sourceTransformation"]
        proof["baselineSourcePath"] = (
            "cases/pmd-clean-a/candidate/src/Worker.java"
        )
        proof.pop("baselineFileSha256", None)
        _write_json(labels_path, labels)
        _refresh(self.root)
        self.assertIn("LABEL016", _codes(self.root))

    def test_ambiguity_members_are_treated_as_an_unordered_set(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        labels["ambiguities"][0]["candidate"].reverse()
        _write_json(labels_path, labels)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertFalse({"ORDER004", "ORDER005"} & codes)

    def test_sarif_label_id_and_marker_are_rejected(self) -> None:
        path = self.root / "cases/pmd-clean-a/baseline.sarif"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["runs"][0]["properties"] = {
            "pmd_clean_a_relationship_main": "GROUND_TRUTH HOLDOUT"
        }
        _write_json(path, document)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("SARIF007", codes)
        self.assertIn("SARIF008", codes)

    def test_typed_json_pointer_and_https_url_are_not_local_paths(self) -> None:
        _write_json(
            self.root / "expected/pointers.json",
            {
                "jsonPointer": "/runs/0/results/0/locations/0",
                "documentation": "https://example.test/docs/a/b",
            },
        )
        _refresh(self.root)
        self.assertNotIn("AMBIENT001", _codes(self.root))

    def test_embedded_absolute_paths_are_rejected(self) -> None:
        _write_json(
            self.root / "expected/paths.json",
            {
                "posix": "captured under /home/runner/work/project/file.sarif",
                "windows": "captured under C:\\work\\project\\file.sarif",
                "uri": "capture source file:///home/runner/work/source.java",
            },
        )
        _refresh(self.root)
        self.assertIn("AMBIENT001", _codes(self.root))

    def test_baseline_candidate_roots_and_sarif_must_be_distinct(self) -> None:
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        family = manifest["families"][0]
        family["candidate"]["sourceRoot"] = family["baseline"]["sourceRoot"]
        family["candidate"]["sarifPath"] = family["baseline"]["sarifPath"]
        _write_json(path, manifest)
        codes = _codes(self.root)
        self.assertIn("MANIFEST008", codes)
        self.assertIn("MANIFEST009", codes)

    def test_source_only_mode_permits_absent_capture_outputs_but_normal_does_not(self) -> None:
        (self.root / "manifest.json").unlink()
        for family in ("pmd-clean-a", "pmd-clean-b"):
            (self.root / f"cases/{family}/baseline.sarif").unlink()
            (self.root / f"cases/{family}/candidate.sarif").unlink()
        self.assertEqual(
            (),
            scan_research_root(self.root, source_only=True),
        )
        self.assertIn("MANIFEST001", _codes(self.root))

    def test_source_only_mode_rejects_pre_capture_marker_and_unexpected_topology(self) -> None:
        source = self.root / "cases/pmd-clean-a/baseline/src/Worker.java"
        source.write_text(
            _source().replace(
                "        error.printStackTrace();",
                "        // HOLDOUT: relationship-one\n"
                "        error.printStackTrace();",
            ),
            encoding="utf-8",
            newline="\n",
        )
        unexpected = self.root / "cases/pmd-clean-a/notes.txt"
        unexpected.write_text("notes", encoding="utf-8", newline="\n")
        codes = {
            finding.code
            for finding in scan_research_root(self.root, source_only=True)
        }
        self.assertIn("SOURCE003", codes)
        self.assertIn("SOURCE005", codes)
        self.assertIn("SOURCEONLY003", codes)

    def test_source_only_mode_enforces_exact_labels_schema_contract(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        original = json.loads(labels_path.read_text(encoding="utf-8"))
        mutations = {
            "schema-version": lambda value: value.__setitem__("schemaVersion", "999"),
            "rule-id": lambda value: value.__setitem__("ruleId", "Other"),
            "extra-field": lambda value: value.__setitem__("extra", True),
            "empty-proof": lambda value: value["relationships"][0].__setitem__(
                "sourceTransformation", {}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                labels = json.loads(json.dumps(original))
                mutate(labels)
                _write_json(labels_path, labels)
                codes = {
                    finding.code
                    for finding in scan_research_root(self.root, source_only=True)
                }
                self.assertIn("LABEL018", codes)
        _write_json(labels_path, original)

    def test_source_only_mode_requires_side_appropriate_proof_hashes(self) -> None:
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        original = json.loads(labels_path.read_text(encoding="utf-8"))
        mutations = (
            ("relationships", 0, "baselineFileSha256"),
            ("new", 0, "candidateFileSha256"),
            ("resolved", 0, "baselineFileSha256"),
            ("ambiguities", 0, "candidateFileSha256"),
        )
        for category, index, key in mutations:
            with self.subTest(category=category, key=key):
                labels = json.loads(json.dumps(original))
                labels[category][index]["sourceTransformation"].pop(key)
                _write_json(labels_path, labels)
                codes = {
                    finding.code
                    for finding in scan_research_root(self.root, source_only=True)
                }
                self.assertIn("LABEL016", codes)
                self.assertIn("LABEL018", codes)
        _write_json(labels_path, original)

    def test_proof_source_must_identify_the_applicable_endpoint_file(self) -> None:
        other = self.root / "cases/pmd-clean-a/baseline/src/Other.java"
        other.write_text(_source(), encoding="utf-8", newline="\n")
        labels_path = self.root / "cases/pmd-clean-a/labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        proof = labels["relationships"][0]["sourceTransformation"]
        proof["baselineSourcePath"] = (
            "cases/pmd-clean-a/baseline/src/Other.java"
        )
        proof["baselineFileSha256"] = hashlib.sha256(other.read_bytes()).hexdigest()
        _write_json(labels_path, labels)
        codes = {
            finding.code
            for finding in scan_research_root(self.root, source_only=True)
        }
        self.assertIn("LABEL019", codes)

    def test_scanner_path_and_hash_are_policy_bound(self) -> None:
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["contamination"]["scannerPath"] = "tools/other.py"
        manifest["contamination"]["scannerSha256"] = "0" * 64
        _write_json(path, manifest)
        self.assertIn("POLICY002", _codes(self.root))

    def test_canonical_scanner_hash_mismatch_is_rejected(self) -> None:
        path = self.root / "manifest.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["contamination"]["scannerSha256"] = "0" * 64
        _write_json(path, manifest)
        codes = _codes(self.root)
        self.assertIn("POLICY003", codes)
        self.assertIn("POLICY004", codes)

    def test_experiment_selected_variant_must_exist_once(self) -> None:
        report = _experiment_report(
            [_experiment_variant("safe"), _experiment_variant("safe")],
            "safe",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT005", codes)
        self.assertIn("EXPERIMENT006", codes)
        self.assertIn("EXPERIMENT007", codes)

    def test_implement_v4_requires_every_projected_gate(self) -> None:
        unsafe = _experiment_variant(
            "unsafe",
            rootConfusions=1,
            scenarioMatrixPassed=False,
        )
        report = _experiment_report([unsafe], "unsafe", "implement-v4")
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT008", _codes(self.root))

    def test_fabricated_passing_projection_cannot_override_failed_evidence(self) -> None:
        variant = _experiment_variant("fabricated")
        release = variant["releaseEvidence"]
        release["developmentCorpus"]["passed"] = False
        release["holdout"]["byProducer"][0]["regressions"] = 1
        report = _experiment_report([variant], "fabricated", "implement-v4")
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT010", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_clean_pmd_metrics_cannot_be_replaced_by_holdout_metrics(self) -> None:
        variant = _experiment_variant("conflated")
        variant["metrics"]["aggregate"] = _metrics(75, 0, 0)
        report = _experiment_report([variant], "conflated", "implement-v4")
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_unexplained_ingestion_failure_blocks_implementation(self) -> None:
        variant = _experiment_variant(
            "ingestion-failure",
            unexplainedIngestionFailures=1,
        )
        variant["ingestion"]["failures"] = 1
        report = _experiment_report(
            [variant],
            "ingestion-failure",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT008", _codes(self.root))

    def test_experiment_gate_projection_must_match_evidence(self) -> None:
        variants = _complete_experiment_variants()
        variants[0]["gateProjection"]["rootConfusions"] = 1
        report = _experiment_report(
            variants,
            "sarif-only-control",
            "document-limitation",
        )
        report["fixedGates"]["minimumPmdRecall"] = 0.1
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT001", codes)
        self.assertIn("EXPERIMENT010", codes)

    def test_complete_predeclared_experiment_matrix_is_accepted(self) -> None:
        report = _experiment_report(
            _complete_experiment_variants(),
            "agreement-only-combination",
            "document-limitation",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        experiment_codes = {
            code for code in _codes(self.root) if code.startswith("EXPERIMENT")
        }
        self.assertEqual(set(), experiment_codes)

        report["decision"] = "implement-v4"
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT008", _codes(self.root))

    def test_manifest_and_implementation_hashes_are_bound_to_admitted_files(self) -> None:
        variants = _complete_experiment_variants()
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        report["implementation"]["sha256"] = "a" * 64
        path = self.root / "expected/experiment-report.json"
        _write_json(path, report)
        _refresh(self.root)
        document = json.loads(path.read_text(encoding="utf-8"))
        document["corpusManifestSha256"] = "0" * 64
        _write_json(path, document)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT013", codes)
        self.assertIn("EXPERIMENT014", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_decision_must_use_the_exact_supported_enum(self) -> None:
        report = _experiment_report(
            _complete_experiment_variants(),
            "agreement-only-combination",
            "IMPLEMENT-V4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT015", _codes(self.root))

    def test_arbitrary_same_blob_cannot_satisfy_implement_v4_evidence_roles(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        evidence_path = "cases/pmd-clean-a/ruleset.xml"
        evidence_sha256 = hashlib.sha256(
            (self.root / evidence_path).read_bytes()
        ).hexdigest()

        def reference(path_key: str, hash_key: str) -> dict[str, str]:
            return {path_key: evidence_path, hash_key: evidence_sha256}

        selected["experimentEvidence"] = reference("path", "sha256")
        selected["releaseEvidence"]["holdout"].update(
            reference("reportPath", "reportSha256")
        )
        selected["releaseEvidence"]["developmentCorpus"].update(
            reference("reportPath", "reportSha256")
        )
        selected["productionApplicability"].update(
            reference("evidencePath", "evidenceSha256")
        )
        for name in ("linux", "windows", "comparison"):
            selected["determinism"][name].update(
                reference("artifactPath", "artifactSha256")
            )
        selected["resources"].update(
            reference("evidencePath", "evidenceSha256")
        )
        for cell in selected["resources"]["cells"]:
            cell.update(reference("artifactPath", "artifactSha256"))
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        report["implementation"].update(reference("path", "sha256"))
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT008", codes)
        self.assertIn("EXPERIMENT016", codes)
        self.assertNotIn("EXPERIMENT014", codes)

    def test_release_report_hash_is_bound_to_admitted_report_bytes(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        selected["releaseEvidence"]["holdout"]["reportPath"] = "manifest.json"
        selected["releaseEvidence"]["holdout"]["reportSha256"] = "0" * 64
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        implementation_path = "tools/scan_contamination.py"
        report["implementation"]["path"] = implementation_path
        report["implementation"]["sha256"] = hashlib.sha256(
            (self.root / implementation_path).read_bytes()
        ).hexdigest()
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT014", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_determinism_booleans_cannot_override_output_digest_difference(self) -> None:
        variants = _complete_experiment_variants()
        determinism = variants[-1]["determinism"]
        determinism["windows"]["firstOutputSha256"] = "f" * 64
        determinism["windows"]["secondOutputSha256"] = "f" * 64
        determinism["linuxWindowsByteIdentical"] = True
        determinism["comparison"]["byteIdentical"] = True
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "document-limitation",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT011", _codes(self.root))

    def test_resource_matrix_requires_every_size_shape_and_os_once(self) -> None:
        variants = _complete_experiment_variants()
        cells = variants[-1]["resources"]["cells"]
        cells[-1] = json.loads(json.dumps(cells[0]))
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "document-limitation",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        self.assertIn("EXPERIMENT011", _codes(self.root))

    def test_each_variant_requires_every_scenario_once(self) -> None:
        for mutation in ("missing", "duplicate"):
            with self.subTest(mutation=mutation):
                variants = _complete_experiment_variants()
                scenarios = variants[0]["scenarios"]
                if mutation == "missing":
                    scenarios.pop()
                else:
                    scenarios[-1] = json.loads(json.dumps(scenarios[0]))
                report = _experiment_report(
                    variants,
                    "sarif-only-control",
                    "implement-v4",
                )
                _write_json(
                    self.root / "expected/experiment-report.json",
                    report,
                )
                _refresh(self.root)
                codes = _codes(self.root)
                self.assertIn("EXPERIMENT011", codes)
                self.assertIn("EXPERIMENT008", codes)

    def test_swapped_root_failure_cannot_project_zero_confusion(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        swapped = selected["scenarios"][8]
        swapped["assertionsPassed"] = False
        swapped["preflightAccepted"] = True
        swapped["acceptedRelationships"] = 1
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_corpus_hash_dependent_green_matrix_cannot_authorize_v4(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        selected["gateProjection"]["corpusSpecificPreflightRequired"] = True
        production = selected["productionApplicability"]
        production["metricsWithoutTrustedTreeHashes"] = _metrics(0, 0, 19)
        production["corpusSpecificPreflightRequired"] = True
        no_hash_mismatch = production["scenariosWithoutTrustedTreeHashes"][5]
        no_hash_mismatch["assertionsPassed"] = False
        no_hash_mismatch["preflightAccepted"] = True
        no_hash_mismatch["acceptedRelationships"] = 1
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        path = self.root / "expected/experiment-report.json"
        _write_json(path, report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT008", codes)
        self.assertNotIn("EXPERIMENT010", codes)
        self.assertNotIn("EXPERIMENT011", codes)

        report["decision"] = "document-limitation"
        _write_json(path, report)
        _refresh(self.root)
        limitation_codes = {
            code for code in _codes(self.root) if code.startswith("EXPERIMENT")
        }
        self.assertEqual(set(), limitation_codes)

    def test_no_hash_swapped_root_matrix_is_derived_not_self_asserted(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        selected["gateProjection"]["corpusSpecificPreflightRequired"] = True
        production = selected["productionApplicability"]
        swapped = production["scenariosWithoutTrustedTreeHashes"][8]
        swapped["assertionsPassed"] = False
        swapped["preflightAccepted"] = True
        swapped["acceptedRelationships"] = 1
        production["corpusSpecificPreflightRequired"] = True
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        path = self.root / "expected/experiment-report.json"
        _write_json(path, report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT008", codes)
        self.assertNotIn("EXPERIMENT010", codes)
        self.assertNotIn("EXPERIMENT011", codes)

    def test_ambiguity_universe_and_refusal_arithmetic_are_bound(self) -> None:
        variants = _complete_experiment_variants()
        selected = variants[-1]
        selected["ambiguity"]["labelledUnits"] = 0
        selected["ambiguity"]["correctRefusals"] = 0
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_all_four_side_ingestions_must_be_evaluated(self) -> None:
        variants = _complete_experiment_variants()
        variants[-1]["ingestion"]["casesEvaluated"] = 0
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_resource_boolean_cannot_override_numeric_budget_failure(self) -> None:
        variants = _complete_experiment_variants()
        resources = variants[-1]["resources"]
        resources["withinDocumentedLimits"] = True
        resources["cells"][0]["candidateEdges"] = 1_000_001
        resources["cells"][0]["maximumComponentSize"] = 13
        resources["cells"][0]["elapsedMilliseconds"] = 10_001
        resources["cells"][0]["peakWorkingSetBytes"] = 512 * 1024 * 1024 + 1
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def test_family_metric_universes_are_eight_and_eleven(self) -> None:
        variants = _complete_experiment_variants()
        by_family = variants[-1]["metrics"]["byFamily"]
        by_family[0] = {"familyId": "pmd-clean-a", **_metrics(19, 0, 0)}
        by_family[1] = {"familyId": "pmd-clean-b", **_metrics(0, 0, 0)}
        report = _experiment_report(
            variants,
            "agreement-only-combination",
            "implement-v4",
        )
        _write_json(self.root / "expected/experiment-report.json", report)
        _refresh(self.root)
        codes = _codes(self.root)
        self.assertIn("EXPERIMENT011", codes)
        self.assertIn("EXPERIMENT008", codes)

    def _add_ordered_relationship(
        self,
        *,
        baseline_uri: str,
        candidate_uri: str,
    ) -> None:
        family_root = self.root / "cases/pmd-clean-a"
        for side, uri in (("baseline", baseline_uri), ("candidate", candidate_uri)):
            source_path = family_root / side / uri
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text(_source(), encoding="utf-8", newline="\n")
        labels_path = family_root / "labels.json"
        labels = json.loads(labels_path.read_text(encoding="utf-8"))
        baseline = _selector(baseline_uri, line=12)
        candidate = _selector(candidate_uri, line=12)
        labels["relationships"].append(
            {
                "id": "pmd-clean-a-relationship-second",
                "expectedClassification": "moved",
                "baseline": baseline,
                "candidate": candidate,
                "sourceTransformation": _proof(
                    self.root,
                    "cases/pmd-clean-a/baseline/src/Worker.java",
                    "cases/pmd-clean-a/candidate/src/Worker.java",
                    "A second relationship is derived independently from source.",
                ),
            }
        )
        _write_json(labels_path, labels)
        for side, selector in (("baseline", baseline), ("candidate", candidate)):
            sarif_path = family_root / f"{side}.sarif"
            document = json.loads(sarif_path.read_text(encoding="utf-8"))
            document["runs"][0]["results"].append(_result(selector))
            _write_json(sarif_path, document)
        _refresh(self.root)


if __name__ == "__main__":
    unittest.main()
