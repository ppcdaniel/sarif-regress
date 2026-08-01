#!/usr/bin/env python3
"""Mutation-focused tests for sparse PMD capture projection and verification."""

from __future__ import annotations

import copy
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from project_pmd_sarif import (
    ALGORITHM_VERSION,
    MAX_JSON_DEPTH,
    ProjectionError,
    project_capture,
    project_document,
    read_strict_json,
    stable_json_bytes,
)
from verify_pmd_capture import (
    CAPTURE_COMMAND,
    DOWNLOAD_COMMAND,
    DOWNLOAD_FILE_SIZE_BLOCKS,
    JAVA_DISTRIBUTION,
    JAVA_VENDOR,
    JAVA_VERSION,
    PMD_ARCHIVE_BYTES,
    PMD_ARCHIVE_NAME,
    PMD_ARCHIVE_PREFIX,
    PMD_ARCHIVE_SHA256,
    PMD_ARCHIVE_URL,
    PMD_HELP_SHA256,
    PMD_VERSION,
    PYTHON_VERSION,
    RUNNER_IMAGE_OS,
    RUNNER_LABEL,
    VerificationError,
    _verify_environment,
    _verify_projection,
    capture_contract,
    capture_contract_sha256,
    environment_evidence,
    expected_capture_command,
    expected_download_command,
    shell_capture_contract,
    verify_capture_command,
    verify_capture_contract,
    verify_capture,
    verify_download_command,
    verify_family_labels,
)


MESSAGE = "Avoid printStackTrace(); use a logger call instead."
CONTRACT_SHA256 = capture_contract_sha256()


def _source(variable: str = "error") -> str:
    return (
        "package sample;\n"
        "\n"
        "final class Worker {\n"
        f"    void report(Exception {variable}) {{\n"
        f"        {variable}.printStackTrace();\n"
        "    }\n"
        "}\n"
    )


def _two_call_source() -> str:
    return (
        "package sample;\n"
        "\n"
        "final class Worker {\n"
        "    void first(Exception alpha) {\n"
        "        alpha.printStackTrace();\n"
        "    }\n"
        "\n"
        "    void second(Exception beta) {\n"
        "        beta.printStackTrace();\n"
        "    }\n"
        "}\n"
    )


def _three_call_source() -> str:
    return (
        "package sample;\n"
        "\n"
        "final class Worker {\n"
        "    void first(Exception alpha) {\n"
        "        alpha.printStackTrace();\n"
        "    }\n"
        "\n"
        "    void second(Exception beta) {\n"
        "        beta.printStackTrace();\n"
        "    }\n"
        "\n"
        "    void third(Exception gamma) {\n"
        "        gamma.printStackTrace();\n"
        "    }\n"
        "}\n"
    )


def _region(variable: str = "error", line: int = 5) -> dict[str, int]:
    statement = f"{variable}.printStackTrace();"
    start = 9
    return {
        "startLine": line,
        "startColumn": start,
        "endLine": line,
        "endColumn": start + len(statement) - 1,
    }


def _result(uri: str, *, variable: str = "error", line: int = 5) -> dict[str, object]:
    return {
        "ruleId": "AvoidPrintStackTrace",
        "ruleIndex": 0,
        "message": {"text": MESSAGE},
        "level": "warning",
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": _region(variable, line),
                }
            }
        ],
    }


def _document(results: list[dict[str, object]]) -> dict[str, object]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PMD",
                        "version": "7.26.0",
                        "rules": [{"id": "AvoidPrintStackTrace"}],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolConfigurationNotifications": [],
                        "toolExecutionNotifications": [],
                    }
                ],
            }
        ],
    }


def _selector(uri: str, *, variable: str = "error", line: int = 5) -> dict[str, object]:
    return {
        "ruleId": "AvoidPrintStackTrace",
        "artifactUri": uri,
        "region": _region(variable, line),
        "message": MESSAGE,
    }


def _write_json(path: Path, value: object, *, sort_keys: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(stable_json_bytes(value, sort_keys=sort_keys))


def _write_family(
    root: Path,
    baseline_document: object,
    candidate_document: object,
    labels: dict[str, object],
) -> Path:
    case_root = root / "pmd-test-family"
    for side in ("baseline", "candidate"):
        source = case_root / side / "source" / "pkg" / "Worker.java"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(_source(), encoding="utf-8", newline="\n")
    _write_json(case_root / "labels.json", labels)
    return case_root


def _labels(
    relationships: list[dict[str, object]],
    *,
    new: list[dict[str, object]] | None = None,
    resolved: list[dict[str, object]] | None = None,
    ambiguities: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "familyId": "pmd-test-family",
        "producerFamily": "pmd",
        "ruleId": "AvoidPrintStackTrace",
        "baselineSarif": "baseline.sarif",
        "candidateSarif": "candidate.sarif",
        "relationships": relationships,
        "new": new or [],
        "resolved": resolved or [],
        "ambiguities": ambiguities or [],
    }


def _proof() -> dict[str, object]:
    return {
        "kind": "source-derived",
        "description": "The source transformation independently establishes continuity.",
        "baselineSourcePath": "baseline/source/pkg/Worker.java",
        "candidateSourcePath": "candidate/source/pkg/Worker.java",
    }


class ProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source_root = self.root / "source"
        source = self.source_root / "pkg" / "Worker.java"
        source.parent.mkdir(parents=True)
        source.write_text(_source(), encoding="utf-8", newline="\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _raw_document(self, *, duplicate: bool = False) -> dict[str, object]:
        uri = (self.source_root / "pkg" / "Worker.java").as_uri()
        result = _result(uri)
        results = [result, copy.deepcopy(result)] if duplicate else [result]
        return _document(results)

    def _project(self, document: object | None = None) -> tuple[Path, Path, Path]:
        raw = self.root / "baseline.raw.sarif"
        projected = self.root / "baseline.sarif"
        audit = self.root / "baseline.projection-audit.json"
        _write_json(raw, document or self._raw_document())
        project_capture(
            raw,
            projected,
            audit,
            self.source_root,
            "pmd-test-family",
            "baseline",
            "cases/pmd-test-family/baseline/source",
            CONTRACT_SHA256,
        )
        return raw, projected, audit

    def test_projection_changes_only_uri_and_preserves_raw_and_order(self) -> None:
        document = self._raw_document(duplicate=True)
        raw, projected, audit = self._project(document)
        self.assertEqual(stable_json_bytes(document, sort_keys=False), raw.read_bytes())
        projected_document, _ = read_strict_json(projected)
        expected = copy.deepcopy(document)
        results = expected["runs"][0]["results"]
        for result in results:
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
                "pkg/Worker.java"
            )
        self.assertEqual(expected, projected_document)
        audit_document, _ = read_strict_json(audit)
        self.assertEqual(ALGORITHM_VERSION, audit_document["algorithmVersion"])
        self.assertEqual(CONTRACT_SHA256, audit_document["captureContractSha256"])
        self.assertEqual(
            [
                "/runs/0/results/0/locations/0/physicalLocation/artifactLocation/uri",
                "/runs/0/results/1/locations/0/physicalLocation/artifactLocation/uri",
            ],
            [change["pointer"] for change in audit_document["changes"]],
        )

    def test_every_representative_non_uri_mutation_is_rejected(self) -> None:
        original = self._raw_document(duplicate=True)
        mutations = {
            "message": lambda value: value["runs"][0]["results"][0]["message"].__setitem__(
                "text", "mutated"
            ),
            "rule": lambda value: value["runs"][0]["results"][0].__setitem__(
                "ruleId", "OtherRule"
            ),
            "result-order": lambda value: value["runs"][0]["results"].reverse(),
            "extra-property": lambda value: value["runs"][0]["results"][0].__setitem__(
                "properties", {"unexpected": True}
            ),
            "ambient-path": lambda value: value["runs"][0].__setitem__(
                "properties", {"checkout": "/home/runner/work/project/output.sarif"}
            ),
            "deleted-level": lambda value: value["runs"][0]["results"][0].pop("level"),
        }
        # Give the second result a different region so reversing it is observable.
        original["runs"][0]["results"][1]["locations"][0]["physicalLocation"]["region"] = (
            _region(line=6)
        )
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source_root = root / "source"
                source = source_root / "pkg" / "Worker.java"
                source.parent.mkdir(parents=True)
                source.write_text(_source(), encoding="utf-8")
                document = copy.deepcopy(original)
                uri = source.as_uri()
                for result in document["runs"][0]["results"]:
                    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
                raw = root / "raw.sarif"
                projected = root / "projected.sarif"
                audit = root / "audit.json"
                _write_json(raw, document)
                project_capture(
                    raw,
                    projected,
                    audit,
                    source_root,
                    "pmd-test-family",
                    "baseline",
                    "cases/pmd-test-family/baseline/source",
                    CONTRACT_SHA256,
                )
                changed, _ = read_strict_json(projected)
                mutation(changed)
                projected.write_bytes(stable_json_bytes(changed, sort_keys=False))
                with self.assertRaises(VerificationError):
                    _verify_projection(
                        raw_path=raw,
                        projected_path=projected,
                        audit_path=audit,
                        source_root=source_root,
                        logical_source_root="cases/pmd-test-family/baseline/source",
                        family_id="pmd-test-family",
                        side="baseline",
                    )

    def test_outside_source_file_uri_is_rejected(self) -> None:
        outside = self.root / "outside.java"
        outside.write_text(_source(), encoding="utf-8")
        with self.assertRaises(ProjectionError):
            project_document(_document([_result(outside.as_uri())]), self.source_root)

    def test_checkout_source_root_cannot_survive_in_an_unprojected_field(self) -> None:
        document = self._raw_document()
        document["runs"][0]["properties"] = {
            "ambientCaptureRoot": self.source_root.as_uri(),
        }
        with self.assertRaises(ProjectionError):
            project_document(document, self.source_root)

    def test_ambient_machine_values_are_rejected_anywhere_in_projection(self) -> None:
        ambient_values = {
            "posix-path": "/home/runner/work/project/output.sarif",
            "single-posix-tmp": "/tmp",
            "single-posix-home": "/home",
            "bare-posix-root": "/",
            "embedded-single-posix": "prefix (/root) suffix",
            "network-posix": "//server/share",
            "embedded-network-posix": "prefix //server/share suffix",
            "windows-path": r"C:\a\project\output.sarif",
            "file-uri": "file:///tmp/unrelated/output.sarif",
            "hostname": "fv-az123-456",
            "embedded-hostname": "captured on fv-az123-456",
            "assigned-hostname": "host=fv-az123-456",
            "timestamp": "2026-08-02T17:04:59Z",
        }
        for name, ambient in ambient_values.items():
            with self.subTest(value=name):
                document = self._raw_document()
                document["runs"][0]["properties"] = {"ambient": ambient}
                with self.assertRaises(ProjectionError):
                    project_document(document, self.source_root)

    def test_typed_json_pointer_and_https_url_are_not_ambient_paths(self) -> None:
        document = self._raw_document()
        properties = {
            "jsonPointer": "/runs/0/results/0/locations/0",
            "documentation": "https://example.test/docs/a/b",
        }
        document["runs"][0]["properties"] = properties
        projected, _, _ = project_document(document, self.source_root)
        self.assertEqual(properties, projected["runs"][0]["properties"])

    def test_duplicate_json_member_is_rejected(self) -> None:
        path = self.root / "duplicate.json"
        path.write_bytes(b'{"version":"2.1.0","version":"2.1.0"}\n')
        with self.assertRaises(ProjectionError):
            read_strict_json(path)

    def test_excessive_nesting_is_rejected_before_json_materialization(self) -> None:
        path = self.root / "deep.json"
        path.write_text(
            "[" * (MAX_JSON_DEPTH + 1) + "0" + "]" * (MAX_JSON_DEPTH + 1),
            encoding="utf-8",
        )
        with mock.patch("project_pmd_sarif.json.loads") as decoder:
            with self.assertRaises(ProjectionError):
                read_strict_json(path)
            decoder.assert_not_called()

    def test_symbolic_source_root_is_rejected_without_resolution(self) -> None:
        alias = self.root / "source-alias"
        try:
            alias.symlink_to(self.source_root, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        uri = (alias / "pkg" / "Worker.java").as_uri()
        with self.assertRaises(ProjectionError):
            project_document(_document([_result(uri)]), alias)

    def test_symbolic_artifact_component_is_rejected_by_anchored_open(self) -> None:
        real = self.source_root / "real"
        real.mkdir()
        (real / "Worker.java").write_text(_source(), encoding="utf-8")
        alias = self.source_root / "linked"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symbolic links unavailable: {error}")
        uri = (alias / "Worker.java").as_uri()
        with self.assertRaises(ProjectionError):
            project_document(_document([_result(uri)]), self.source_root)

    def test_noncanonical_logical_root_and_family_id_are_rejected(self) -> None:
        raw, _, _ = self._project()
        for family_id, logical in (
            ("pmd-test-family", "cases//pmd-test-family/baseline/source"),
            ("PMD Test", "cases/pmd-test-family/baseline/source"),
            ("pmd-test-family", "cases\\pmd-test-family\\baseline\\source"),
        ):
            with (
                self.subTest(family_id=family_id, logical=logical),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                with self.assertRaises(ProjectionError):
                    project_capture(
                        raw,
                        root / "projected.sarif",
                        root / "audit.json",
                        self.source_root,
                        family_id,
                        "baseline",
                        logical,
                        CONTRACT_SHA256,
                    )


class CaptureContractTests(unittest.TestCase):
    def test_shell_contract_exactly_reproduces_canonical_contract(self) -> None:
        observed = shell_capture_contract(
            pmd_version=PMD_VERSION,
            archive_name=PMD_ARCHIVE_NAME,
            archive_url=PMD_ARCHIVE_URL,
            archive_bytes=PMD_ARCHIVE_BYTES,
            archive_sha256=PMD_ARCHIVE_SHA256,
            archive_prefix=PMD_ARCHIVE_PREFIX,
            help_sha256=PMD_HELP_SHA256,
            python_version=PYTHON_VERSION,
            java_distribution=JAVA_DISTRIBUTION,
            java_vendor=JAVA_VENDOR,
            java_version=JAVA_VERSION,
            runner_label=RUNNER_LABEL,
            runner_image_os=RUNNER_IMAGE_OS,
            projection_algorithm_version=ALGORITHM_VERSION,
            capture_arguments=CAPTURE_COMMAND,
            download_arguments=DOWNLOAD_COMMAND,
            download_file_size_blocks=DOWNLOAD_FILE_SIZE_BLOCKS,
        )
        self.assertEqual(capture_contract(), observed)
        self.assertEqual(CONTRACT_SHA256, verify_capture_contract(observed))

    def test_every_producer_contract_constant_mutation_is_rejected(self) -> None:
        producer = capture_contract()["producer"]
        self.assertIsInstance(producer, dict)
        for key in producer:
            with self.subTest(field=key):
                observed = copy.deepcopy(capture_contract())
                original = observed["producer"][key]
                observed["producer"][key] = (
                    original + 1 if isinstance(original, int) else f"{original}-mutated"
                )
                with self.assertRaises(VerificationError):
                    verify_capture_contract(observed)

    def test_runtime_pmd_argv_rejects_flag_or_path_drift(self) -> None:
        executable = "/tmp/pmd/bin/pmd"
        source_root = "/tmp/source"
        raw_capture = "/tmp/output/baseline.raw.sarif"
        ruleset = "/tmp/cases/pmd-ruleset.xml"
        arguments = expected_capture_command(
            executable,
            source_root,
            raw_capture,
            ruleset,
        )
        verify_capture_command(
            arguments,
            executable,
            source_root,
            raw_capture,
            ruleset,
        )
        mutations = {
            "flag": tuple(
                "--cache" if argument == "--no-cache" else argument
                for argument in arguments
            ),
            "source-side": tuple(
                "/tmp/candidate" if argument == source_root else argument
                for argument in arguments
            ),
            "order": (*arguments[:2], arguments[3], arguments[2], *arguments[4:]),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(VerificationError):
                verify_capture_command(
                    mutation,
                    executable,
                    source_root,
                    raw_capture,
                    ruleset,
                )

    def test_download_has_exact_transfer_and_inherited_file_ceilings(self) -> None:
        destination = "/tmp/pmd-dist.zip"
        arguments = expected_download_command(destination)
        self.assertEqual("--disable", arguments[1])
        maximum_index = arguments.index("--max-filesize")
        self.assertEqual(str(PMD_ARCHIVE_BYTES), arguments[maximum_index + 1])
        verify_download_command(
            arguments,
            destination,
            DOWNLOAD_FILE_SIZE_BLOCKS,
        )
        mutations = {
            "curlrc-enabled": arguments[:1] + arguments[2:],
            "missing-transfer-ceiling": (
                arguments[:maximum_index] + arguments[maximum_index + 2 :]
            ),
            "larger-transfer-ceiling": (
                arguments[: maximum_index + 1]
                + (str(PMD_ARCHIVE_BYTES + 1),)
                + arguments[maximum_index + 2 :]
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(VerificationError):
                verify_download_command(
                    mutation,
                    destination,
                    DOWNLOAD_FILE_SIZE_BLOCKS,
                )
        with self.assertRaises(VerificationError):
            verify_download_command(
                arguments,
                destination,
                DOWNLOAD_FILE_SIZE_BLOCKS + 1,
            )

    def test_environment_verification_does_not_trust_artifact_runner_values(self) -> None:
        source_sha = "0" * 40
        image_version = "20260802.1.0"
        evidence = environment_evidence(
            source_sha,
            RUNNER_IMAGE_OS,
            image_version,
            CONTRACT_SHA256,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture-environment.json"
            _write_json(path, evidence, sort_keys=True)
            _verify_environment(
                path,
                source_sha,
                RUNNER_IMAGE_OS,
                image_version,
            )
            fabricated = copy.deepcopy(evidence)
            fabricated["runner"]["imageOS"] = "FABRICATED"
            fabricated["runner"]["imageVersion"] = "FABRICATED"
            path.write_bytes(stable_json_bytes(fabricated, sort_keys=True))
            with self.assertRaises(VerificationError):
                _verify_environment(
                    path,
                    source_sha,
                    RUNNER_IMAGE_OS,
                    image_version,
                )
        with self.assertRaises(VerificationError):
            environment_evidence(
                source_sha,
                RUNNER_IMAGE_OS,
                "FABRICATED",
                CONTRACT_SHA256,
            )


class LabelVerificationTests(unittest.TestCase):
    def test_relationship_order_leak_is_label_array_order_invariant(self) -> None:
        relative = "pkg/Worker.java"
        positions = (("alpha", 5), ("beta", 9), ("gamma", 13))
        document = _document(
            [_result(relative, variable=variable, line=line) for variable, line in positions]
        )
        for direction, candidate_positions in (
            ("forward", positions),
            ("reverse", tuple(reversed(positions))),
        ):
            relationships = []
            for (baseline_variable, baseline_line), (
                candidate_variable,
                candidate_line,
            ) in zip(positions, candidate_positions):
                baseline = _selector(
                    relative,
                    variable=baseline_variable,
                    line=baseline_line,
                )
                candidate = _selector(
                    relative,
                    variable=candidate_variable,
                    line=candidate_line,
                )
                relationships.append(
                    {
                        "id": f"relationship-{baseline_variable}",
                        "expectedClassification": (
                            "unchanged" if baseline == candidate else "modified"
                        ),
                        "baseline": baseline,
                        "candidate": candidate,
                        "sourceTransformation": _proof(),
                    }
                )
            for label_order in ((0, 1, 2), (2, 1, 0), (1, 2, 0)):
                with (
                    self.subTest(direction=direction, label_order=label_order),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    ordered = [copy.deepcopy(relationships[index]) for index in label_order]
                    case_root = _write_family(
                        root,
                        document,
                        document,
                        _labels(ordered),
                    )
                    for side in ("baseline", "candidate"):
                        (case_root / side / "source/pkg/Worker.java").write_text(
                            _three_call_source(),
                            encoding="utf-8",
                            newline="\n",
                        )
                    with self.assertRaises(VerificationError):
                        verify_family_labels(case_root, document, document)

    def test_invalid_pmd_invocation_topology_is_rejected(self) -> None:
        mutations = {
            "missing": lambda invocation, run, document: run.pop("invocations"),
            "multiple-runs": lambda invocation, run, document: document["runs"].append(
                copy.deepcopy(run)
            ),
            "unsuccessful": lambda invocation, run, document: invocation.__setitem__(
                "executionSuccessful", False
            ),
            "missing-notification-array": lambda invocation, run, document: invocation.pop(
                "toolExecutionNotifications"
            ),
            "configuration-error": lambda invocation, run, document: invocation.__setitem__(
                "toolConfigurationNotifications",
                [{"level": "error", "message": {"text": "invalid ruleset"}}],
            ),
            "execution-warning": lambda invocation, run, document: invocation.__setitem__(
                "toolExecutionNotifications",
                [{"level": "warning", "message": {"text": "analysis warning"}}],
            ),
            "execution-error": lambda invocation, run, document: invocation.__setitem__(
                "toolExecutionNotifications",
                [{"level": "error", "message": {"text": "analysis failed"}}],
            ),
        }
        for name, mutate in mutations.items():
            with (
                self.subTest(mutation=name),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                relative = "pkg/Worker.java"
                document = _document([_result(relative)])
                run = document["runs"][0]
                invocation = run["invocations"][0]
                mutate(invocation, run, document)
                relationship = {
                    "id": "relationship-one",
                    "expectedClassification": "unchanged",
                    "baseline": _selector(relative),
                    "candidate": _selector(relative),
                    "sourceTransformation": _proof(),
                }
                case_root = _write_family(
                    root,
                    document,
                    document,
                    _labels([relationship]),
                )
                with self.assertRaises(VerificationError):
                    verify_family_labels(case_root, document, document)

    def test_unassigned_sarif_endpoint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "pkg/Worker.java"
            document = _document(
                [
                    _result(relative, variable="alpha", line=5),
                    _result(relative, variable="beta", line=9),
                ]
            )
            relationship = {
                "id": "relationship-one",
                "expectedClassification": "unchanged",
                "baseline": _selector(relative, variable="alpha", line=5),
                "candidate": _selector(relative, variable="alpha", line=5),
                "sourceTransformation": _proof(),
            }
            case_root = _write_family(
                root,
                document,
                document,
                _labels([relationship]),
            )
            for side in ("baseline", "candidate"):
                (case_root / side / "source/pkg/Worker.java").write_text(
                    _two_call_source(),
                    encoding="utf-8",
                    newline="\n",
                )
            with self.assertRaises(VerificationError):
                verify_family_labels(case_root, document, document)

    def test_ambiguity_member_arrays_are_order_invariant(self) -> None:
        relative = "pkg/Worker.java"
        multiple_results = [
            _result(relative, variable="alpha", line=5),
            _result(relative, variable="beta", line=9),
        ]
        multiple_selectors = [
            _selector(relative, variable="alpha", line=5),
            _selector(relative, variable="beta", line=9),
        ]
        for shape, multiple_side in (
            ("one-to-many", "candidate"),
            ("many-to-one", "baseline"),
        ):
            for reversed_order in (False, True):
                with (
                    self.subTest(shape=shape, reversed=reversed_order),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    documents = {
                        "baseline": _document([_result(relative)]),
                        "candidate": _document([_result(relative)]),
                    }
                    documents[multiple_side] = _document(
                        copy.deepcopy(multiple_results)
                    )
                    ordered = copy.deepcopy(multiple_selectors)
                    if reversed_order:
                        ordered.reverse()
                    ambiguity = {
                        "id": "ambiguity-main",
                        "expected": "refuse",
                        "shape": shape,
                        "baseline": (
                            ordered
                            if multiple_side == "baseline"
                            else [_selector(relative)]
                        ),
                        "candidate": (
                            ordered
                            if multiple_side == "candidate"
                            else [_selector(relative)]
                        ),
                        "sourceTransformation": _proof(),
                    }
                    case_root = _write_family(
                        root,
                        documents["baseline"],
                        documents["candidate"],
                        _labels([], ambiguities=[ambiguity]),
                    )
                    (case_root / multiple_side / "source/pkg/Worker.java").write_text(
                        _two_call_source(),
                        encoding="utf-8",
                        newline="\n",
                    )
                    verify_family_labels(
                        case_root,
                        documents["baseline"],
                        documents["candidate"],
                    )

    def test_ambiguous_duplicate_selector_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "pkg/Worker.java"
            duplicate_results = [_result(relative), _result(relative)]
            document = _document(duplicate_results)
            relationship = {
                "id": "relationship-one",
                "expectedClassification": "unchanged",
                "baseline": _selector(relative),
                "candidate": _selector(relative),
                "sourceTransformation": _proof(),
            }
            case_root = _write_family(root, document, document, _labels([relationship]))
            with self.assertRaises(VerificationError):
                verify_family_labels(case_root, document, document)

    def test_endpoint_reuse_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "pkg/Worker.java"
            document = _document([_result(relative)])
            relationship = {
                "id": "relationship-one",
                "expectedClassification": "unchanged",
                "baseline": _selector(relative),
                "candidate": _selector(relative),
                "sourceTransformation": _proof(),
            }
            labels = _labels(
                [relationship],
                new=[
                    {
                        "id": "new-one",
                        "expectedClassification": "new",
                        "candidate": _selector(relative),
                        "sourceTransformation": _proof(),
                    }
                ],
            )
            case_root = _write_family(root, document, document, labels)
            with self.assertRaises(VerificationError):
                verify_family_labels(case_root, document, document)

    def test_sparse_fingerprint_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = "pkg/Worker.java"
            result = _result(relative)
            result["partialFingerprints"] = {"primaryLocationLineHash": "leak"}
            document = _document([result])
            relationship = {
                "id": "relationship-one",
                "expectedClassification": "unchanged",
                "baseline": _selector(relative),
                "candidate": _selector(relative),
                "sourceTransformation": _proof(),
            }
            case_root = _write_family(root, document, document, _labels([relationship]))
            with self.assertRaises(VerificationError):
                verify_family_labels(case_root, document, document)


class CommandLineTests(unittest.TestCase):
    def test_verifier_imports_with_capture_script_invocation(self) -> None:
        script = Path(__file__).with_name("verify_pmd_capture.py")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run(
                [sys.executable, "-B", str(script), "--help"],
                cwd=directory,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_shell_contract_cli_binds_dash_prefixed_templates(self) -> None:
        script = Path(__file__).with_name("verify_pmd_capture.py").resolve()
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        command = [
            sys.executable,
            "-B",
            str(script),
            "verify-contract",
            "--pmd-version",
            PMD_VERSION,
            "--archive-name",
            PMD_ARCHIVE_NAME,
            "--archive-url",
            PMD_ARCHIVE_URL,
            "--archive-bytes",
            str(PMD_ARCHIVE_BYTES),
            "--archive-sha256",
            PMD_ARCHIVE_SHA256,
            "--archive-prefix",
            PMD_ARCHIVE_PREFIX,
            "--help-sha256",
            PMD_HELP_SHA256,
            "--python-version",
            PYTHON_VERSION,
            "--java-distribution",
            JAVA_DISTRIBUTION,
            "--java-vendor",
            JAVA_VENDOR,
            "--java-version",
            JAVA_VERSION,
            "--runner-label",
            RUNNER_LABEL,
            "--runner-image-os",
            RUNNER_IMAGE_OS,
            "--projection-algorithm-version",
            ALGORITHM_VERSION,
            "--download-file-size-blocks",
            str(DOWNLOAD_FILE_SIZE_BLOCKS),
            *(f"--capture-argument={argument}" for argument in CAPTURE_COMMAND),
            *(f"--download-argument={argument}" for argument in DOWNLOAD_COMMAND),
        ]
        completed = subprocess.run(
            command,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual(f"{CONTRACT_SHA256}\n", completed.stdout)
        mutated = command.copy()
        mutated[mutated.index(PMD_VERSION)] = "7.26.1"
        rejected = subprocess.run(
            mutated,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
        )
        self.assertNotEqual(0, rejected.returncode)

    def test_dash_prefixed_runtime_argv_survives_cli_forwarding_exactly(self) -> None:
        script = Path(__file__).with_name("verify_pmd_capture.py").resolve()
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = str(root / "pmd/bin/pmd")
            source_root = str(root / "source")
            raw_capture = str(root / "output/raw.sarif")
            ruleset = str(root / "case/pmd-ruleset.xml")
            pmd_arguments = expected_capture_command(
                executable,
                source_root,
                raw_capture,
                ruleset,
            )
            command = [
                sys.executable,
                "-B",
                str(script),
                "verify-command",
                "--executable",
                executable,
                "--source-root",
                source_root,
                "--raw-capture",
                raw_capture,
                "--ruleset",
                ruleset,
                *(f"--argument={argument}" for argument in pmd_arguments),
            ]
            completed = subprocess.run(
                command,
                cwd=directory,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

            mutated = [
                "--cache" if argument == "--no-cache" else argument
                for argument in pmd_arguments
            ]
            rejected = subprocess.run(
                command[:12] + [f"--argument={argument}" for argument in mutated],
                cwd=directory,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertNotEqual(0, rejected.returncode)

            destination = str(root / "pmd.zip")
            download_arguments = expected_download_command(destination)
            download_command = [
                sys.executable,
                "-B",
                str(script),
                "verify-download-command",
                "--destination",
                destination,
                "--file-size-limit-blocks",
                str(DOWNLOAD_FILE_SIZE_BLOCKS),
                *(f"--argument={argument}" for argument in download_arguments),
            ]
            completed = subprocess.run(
                download_command,
                cwd=directory,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)

    def test_verifier_rejects_symbolic_research_root_without_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            research = root / "research"
            capture = root / "capture"
            research.mkdir()
            capture.mkdir()
            alias = root / "research-alias"
            try:
                alias.symlink_to(research, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaises(VerificationError):
                verify_capture(
                    alias,
                    capture,
                    "0" * 40,
                    RUNNER_IMAGE_OS,
                    "20260802.1.0",
                )


if __name__ == "__main__":
    unittest.main()
