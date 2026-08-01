#!/usr/bin/env python3
"""Fail closed when the sparse-SARIF research corpus leaks ground truth."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Iterable, Iterator, Mapping, Sequence


POLICY_VERSION: Final = "sparse-sarif-contamination/v1"
MAX_FILES: Final = 4096
MAX_TOTAL_BYTES: Final = 512 * 1024 * 1024
MAX_JSON_BYTES: Final = 64 * 1024 * 1024
MAX_TEXT_BYTES: Final = 8 * 1024 * 1024
MAX_JSON_DEPTH: Final = 64
MAX_JSON_NODES: Final = 1_000_000
MAX_RESULTS: Final = 10_000
MAX_LABEL_TOKENS: Final = 4096
MAX_DIAGNOSTIC_DETAIL: Final = 240
MAX_DIRECTORIES: Final = 4096
MAX_DIRECTORY_DEPTH: Final = 64
MAX_DIRECTORY_ENTRIES: Final = MAX_FILES + MAX_DIRECTORIES
MIN_NORMALIZED_LABEL_ID_LENGTH: Final = 12

TEXT_SUFFIXES: Final = frozenset(
    {
        ".java",
        ".json",
        ".md",
        ".py",
        ".sarif",
        ".sha256",
        ".txt",
        ".xml",
        ".yml",
        ".yaml",
    }
)

MARKER_PATTERN: Final = re.compile(
    r"(?ix)"
    r"(?:\bHOLDOUT\b|"
    r"\bGROUND[-_ ]?TRUTH\b|"
    r"\bIDENTITY[-_ :]+(?:ID|KEY|MARKER)\b|"
    r"\bCASE(?:[-_ ]?(?:ID|KEY|MARKER))[-_:]?\b|"
    r"\b(?:RELATIONSHIP|AMBIGUITY|MATCH)[-_ ]?(?:ID|KEY|MARKER)[-_:]?\b)"
)
SUSPICIOUS_IDENTIFIER_PATTERN: Final = re.compile(
    r"(?ix)^"
    r"(?:case|finding|match|pair|identity|relationship|ambiguity|"
    r"resolved|newfinding|groundtruth|gt)"
    r"(?:id|key|marker)?[_$-]*[0-9]{1,6}$"
    r"|^(?:baseline|candidate)(?:match|pair|identity|relationship)"
    r"(?:id|key|marker)?[_$-]*[0-9A-Za-z_$-]*$"
)
CORRESPONDENCE_COMMENT_PATTERN: Final = re.compile(
    r"(?ix)(?:"
    r"\bground[-_ ]?truth\b|\bone-to-many\b|\bmany-to-one\b|"
    r"\bsame\s+(?:finding|issue)\b|"
    r"\b(?:baseline|candidate)\b[^\r\n]{0,80}"
    r"\b(?:correspond(?:s|ing)?|matches?|paired?|identity|relationship)\b|"
    r"\b(?:correspond(?:s|ing)?|matches?|paired?)\b[^\r\n]{0,40}"
    r"\b(?:baseline|candidate|finding|issue|identity|relationship)\b|"
    r"\b(?:identity|relationship|ambiguity|match)[-_ ]?(?:id|key|marker)\b)"
)
RESULT_INDEX_KEY_PATTERN: Final = re.compile(
    r"(?i)^(?:(?:baseline|candidate))?results?(?:index|indices)$"
)
RESULT_INDEX_VALUE_PATTERN: Final = re.compile(
    r"(?ix)(?:\bresults?\s*\[\s*[0-9]+\s*\]|"
    r"/results/[0-9]+|\bresults?\s*(?:index|\#)\s*[0-9]+)"
)
POSIX_LOCAL_PATH_PATTERN: Final = re.compile(
    r"(?ix)(?:"
    r"(?<![A-Za-z0-9+.\-:/])file:/+[^\s\"'<>]+|"
    r"(?<![A-Za-z0-9+.\-:/])/(?!/)(?:[^/\s\"'<>]+/)+[^/\s\"'<>]+)"
)
WINDOWS_LOCAL_PATH_PATTERN: Final = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:"
    r"[A-Za-z]:[\\/]|\\\\(?:\?|\.)[\\/]|\\\\[^\\/\s]+[\\/])"
)
TIMESTAMP_PATTERN: Final = re.compile(
    r"\b[12][0-9]{3}-[01][0-9]-[0-3][0-9]"
    r"T[0-2][0-9]:[0-5][0-9]:[0-6][0-9](?:\.[0-9]+)?(?:Z|[+-][0-2][0-9]:[0-5][0-9])\b"
)
HOST_VALUE_PATTERN: Final = re.compile(
    r"(?ix)^(?:localhost|fv-az[0-9]+|desktop-[a-z0-9-]+|"
    r"runner(?:-[a-z0-9-]+)?|ip-[0-9-]+|[a-z0-9-]+\.local)$"
)
HOST_KEYS: Final = frozenset(
    {"hostname", "machinename", "computername", "host"}
)
FIXED_EXPERIMENT_GATES: Final = {
    "minimumPmdPrecision": 0.95,
    "minimumPmdRecall": 0.8,
    "minimumAggregatePrecision": 0.95,
    "minimumAggregateRecall": 0.9,
    "maximumSilentlyMatchedAmbiguity": 0,
    "maximumSourceSideLeakage": 0,
    "maximumContainmentRegressions": 0,
    "maximumRootConfusions": 0,
    "maximumUnexplainedIngestionFailures": 0,
    "maximumStructuralFailures": 0,
    "requireDevelopmentCorpusGreen": True,
    "requireExistingProducerNoRegression": True,
    "requireCrossPlatformByteIdentity": True,
    "requireResourceBudgets": True,
    "requireScenarioMatrixGreen": True,
    "requireCorpusIndependentEvidence": True,
}
EXPERIMENT_VARIANT_IDS: Final = (
    "sarif-only-control",
    "exact-region-snippet",
    "token-window",
    "relative-context",
    "agreement-only-combination",
)
EXPERIMENT_SCENARIO_IDS: Final = (
    "exact-unchanged-source-location",
    "region-drift-equivalent-token-context",
    "file-method-movement-equivalent-token-context",
    "repeated-context-ambiguity",
    "missing-source-file",
    "mismatched-source-snapshot",
    "baseline-root-bound-to-candidate",
    "candidate-root-bound-to-baseline",
    "both-roots-swapped",
    "same-observation-different-method-file",
)
FAIL_CLOSED_SCENARIOS: Final = frozenset(EXPERIMENT_SCENARIO_IDS[4:9])
MAX_EXPERIMENT_CANDIDATE_EDGES: Final = 1_000_000
MAX_EXPERIMENT_COMPONENT_SIZE: Final = 12
RESOURCE_RUNTIME_BUDGETS: Final = {
    1_000: (10_000, 512 * 1024 * 1024),
    10_000: (20_000, 768 * 1024 * 1024),
    100_000: (60_000, 1024 * 1024 * 1024),
}
RESOURCE_CELL_KEYS: Final = tuple(
    (operating_system, finding_count, dataset)
    for operating_system in ("ubuntu", "windows")
    for finding_count in (1_000, 10_000, 100_000)
    for dataset in ("unique", "pathological")
)
IMPLEMENT_V4_ROLE_VALIDATORS_AVAILABLE: Final = False
PMD_SOURCE_COMMIT: Final = "8fd38edf285a33e1164f66205ebe243441db9557"
PMD_PROJECT_URL: Final = "https://github.com/pmd/pmd"
PMD_RELEASE_URL: Final = (
    "https://github.com/pmd/pmd/releases/tag/pmd_releases%2F7.26.0"
)
PMD_LICENSE_URL: Final = (
    "https://github.com/pmd/pmd/blob/"
    f"{PMD_SOURCE_COMMIT}/LICENSE"
)
CAPTURE_CONTRACT_VERSION: Final = "pmd-authentic-sparse-capture/v1"
PROJECTION_ALGORITHM_VERSION: Final = "pmd-file-uri-prefix-projection/v1"
CAPTURE_COMMAND: Final = (
    "pmd",
    "check",
    "--dir",
    ".",
    "--format",
    "sarif",
    "--no-cache",
    "--no-fail-on-violation",
    "--no-progress",
    "--relativize-paths-with",
    "<side-source-root>",
    "--report-file",
    "<raw-capture>",
    "--rulesets",
    "<family-ruleset>",
    "--threads",
    "0",
    "--use-version",
    "java-17",
)
DOWNLOAD_COMMAND: Final = (
    "curl",
    "--disable",
    "--fail",
    "--location",
    "--max-filesize",
    "<archive-bytes>",
    "--proto",
    "=https",
    "--retry",
    "3",
    "--retry-all-errors",
    "--show-error",
    "--silent",
    "--tlsv1.2",
    "--output",
    "<archive-destination>",
    "<archive-url>",
)


@dataclass(frozen=True, order=True)
class Finding:
    """One deterministic, checkout-independent rejection."""

    path: str
    code: str
    detail: str

    def render(self) -> str:
        return f"{self.code} {self.path}: {self.detail}"


class DuplicateKeyError(ValueError):
    """Raised when strict JSON encounters a repeated object member."""


class Scanner:
    """Scans one bounded research tree without following filesystem links."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.files: dict[str, Path] = {}
        self.payloads: dict[str, bytes] = {}
        self.json_documents: dict[str, object] = {}
        self.findings: set[Finding] = set()
        self.label_ids: dict[str, str] = {}
        self.normalized_label_ids: dict[str, str] = {}
        self.read_bytes = 0

    def scan(self, *, source_only: bool = False) -> tuple[Finding, ...]:
        self._enumerate_tree()
        self._scan_text_and_json()
        if source_only:
            self._scan_source_only()
            return self._ordered_findings()
        self._scan_expected_checksums()
        manifest = self.json_documents.get("manifest.json")
        if not isinstance(manifest, dict):
            self._add("MANIFEST001", "manifest.json", "missing or invalid manifest object")
            return self._ordered_findings()
        self._scan_integrity(manifest)
        self._scan_manifest(manifest)
        return self._ordered_findings()

    def _scan_source_only(self) -> None:
        """Validate the label/source topology before producer capture exists."""

        label_paths = sorted(
            relative
            for relative in self.files
            if re.fullmatch(r"cases/[^/]+/labels\.json", relative)
        )
        if not 2 <= len(label_paths) <= 16:
            self._add(
                "SOURCEONLY001",
                "cases",
                "source-only mode requires 2 through 16 family label files",
            )
            return
        records: list[
            tuple[Mapping[str, object], str, dict[str, tuple[Mapping[str, object], str, str, object]]]
        ] = []
        all_tokens: set[str] = set()
        family_ids: set[str] = set()
        allowed_files: set[str] = set()
        for labels_path in label_paths:
            labels = self.json_documents.get(labels_path)
            if not isinstance(labels, dict):
                self._add("LABEL001", labels_path, "labels are missing or invalid")
                continue
            self._validate_labels_contract(labels, labels_path)
            parts = PurePosixPath(labels_path).parts
            directory_family = parts[1]
            family_id = labels.get("familyId")
            if (
                not isinstance(family_id, str)
                or family_id != directory_family
                or family_id in family_ids
                or labels.get("producerFamily") != "pmd"
            ):
                self._add(
                    "SOURCEONLY002",
                    labels_path,
                    "label family identity does not match its unique directory",
                )
                continue
            family_ids.add(family_id)
            family_root = f"cases/{family_id}"
            sides: dict[
                str, tuple[Mapping[str, object], str, str, object]
            ] = {}
            for side_name in ("baseline", "candidate"):
                side_prefix = f"{family_root}/{side_name}/"
                source_components = {
                    PurePosixPath(relative).parts[3]
                    for relative in self.files
                    if relative.startswith(side_prefix)
                    and len(PurePosixPath(relative).parts) >= 5
                }
                endpoint_uris: set[str] = set()
                for category in ("relationships", "new", "resolved", "ambiguities"):
                    entries = labels.get(category)
                    if not isinstance(entries, list):
                        continue
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        endpoint = entry.get(side_name)
                        selectors = endpoint if isinstance(endpoint, list) else [endpoint]
                        endpoint_uris.update(
                            selector["artifactUri"]
                            for selector in selectors
                            if isinstance(selector, dict)
                            and isinstance(selector.get("artifactUri"), str)
                        )
                root_candidates = [f"{family_root}/{side_name}"] + [
                    f"{family_root}/{side_name}/{component}"
                    for component in sorted(source_components)
                ]
                valid_roots = [
                    candidate
                    for candidate in root_candidates
                    if endpoint_uris
                    and all(f"{candidate}/{uri}" in self.files for uri in endpoint_uris)
                ]
                if len(valid_roots) != 1:
                    self._add(
                        "SOURCEONLY003",
                        f"{family_root}/{side_name}",
                        "side source root cannot be derived uniquely from label endpoints",
                    )
                    continue
                source_root = valid_roots[0]
                source_files = sorted(
                    relative
                    for relative in self.files
                    if relative.startswith(source_root + "/")
                )
                if not source_files:
                    self._add(
                        "SOURCE001",
                        source_root,
                        "source root contains no files",
                    )
                for source_file in source_files:
                    if PurePosixPath(source_file).suffix != ".java":
                        self._add(
                            "SOURCEONLY003",
                            source_file,
                            "source roots may contain only Java source files",
                        )
                sides[side_name] = ({}, source_root, "", [])
                allowed_files.update(source_files)
            allowed_files.add(labels_path)
            rulesets = sorted(
                relative
                for relative in self.files
                if re.fullmatch(rf"{re.escape(family_root)}/[^/]+\.xml", relative)
            )
            if len(rulesets) != 1:
                self._add(
                    "SOURCEONLY003",
                    family_root,
                    "family must contain exactly one PMD ruleset",
                )
            else:
                allowed_files.add(rulesets[0])
            for key in ("baselineSarif", "candidateSarif"):
                declared = labels.get(key)
                if _is_canonical_relative_path(declared):
                    candidate = (
                        PurePosixPath(labels_path).parent / str(declared)
                    ).as_posix()
                    if candidate in self.files:
                        allowed_files.add(candidate)
            all_tokens.update(self._label_tokens(labels, labels_path))
            if set(sides) == {"baseline", "candidate"}:
                records.append((labels, labels_path, sides))

        for relative in sorted(self.files):
            if relative.startswith("cases/") and relative not in allowed_files:
                self._add(
                    "SOURCEONLY003",
                    relative,
                    "unexpected file in source-only family topology",
                )
        if len(all_tokens) > MAX_LABEL_TOKENS:
            self._add("LIMIT006", "cases", f"label tokens exceed {MAX_LABEL_TOKENS}")
            all_tokens = set(sorted(all_tokens)[:MAX_LABEL_TOKENS])
        for labels, labels_path, sides in records:
            for side_name in ("baseline", "candidate"):
                source_root = sides[side_name][1]
                for relative in sorted(self.files):
                    if relative.startswith(source_root + "/"):
                        self._scan_source(relative, all_tokens)
            self._scan_proof_sources(labels, labels_path, sides)
            relationships = labels.get("relationships")
            if isinstance(relationships, list):
                baseline_keys: list[tuple[object, ...]] = []
                candidate_keys: list[tuple[object, ...]] = []
                for relationship in relationships:
                    if not isinstance(relationship, dict):
                        continue
                    baseline = selector_from_label(relationship.get("baseline"))
                    candidate = selector_from_label(relationship.get("candidate"))
                    if baseline is None or candidate is None:
                        continue
                    baseline_keys.append(baseline)
                    candidate_keys.append(candidate)
                if len(baseline_keys) >= 2:
                    self._scan_source_order_leakage(
                        labels_path,
                        sides,
                        baseline_keys,
                        candidate_keys,
                    )

    def _ordered_findings(self) -> tuple[Finding, ...]:
        return tuple(sorted(self.findings))

    def _add(self, code: str, path: str, detail: str) -> None:
        stable_detail = " ".join(detail.split())
        if len(stable_detail) > MAX_DIAGNOSTIC_DETAIL:
            digest = hashlib.sha256(stable_detail.encode("utf-8")).hexdigest()[:16]
            stable_detail = (
                stable_detail[: MAX_DIAGNOSTIC_DETAIL - 25]
                + f"… [sha256:{digest}]"
            )
        self.findings.add(Finding(path, code, stable_detail))

    def _enumerate_tree(self) -> None:
        try:
            root_status = self.root.lstat()
        except OSError:
            self._add("FS001", ".", "research root is missing or unreadable")
            return
        if (
            stat.S_ISLNK(root_status.st_mode)
            or not stat.S_ISDIR(root_status.st_mode)
            or self._is_reparse_point(root_status, ".")
        ):
            self._add("FS001", ".", "research root must be a real directory")
            return

        if self._supports_anchored_enumeration():
            self._enumerate_tree_anchored()
        else:
            self._enumerate_tree_portable()

    @staticmethod
    def _supports_anchored_enumeration() -> bool:
        return (
            os.scandir in os.supports_fd
            and os.open in os.supports_dir_fd
            and bool(getattr(os, "O_DIRECTORY", 0))
            and bool(getattr(os, "O_NOFOLLOW", 0))
        )

    def _bounded_entries(
        self,
        directory: int | Path,
        relative: str,
    ) -> list[os.DirEntry[str]] | None:
        """Materialize at most one policy-bounded directory before sorting."""

        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entries.append(entry)
                    if len(entries) > MAX_DIRECTORY_ENTRIES:
                        self._add(
                            "LIMIT010",
                            relative,
                            f"directory entries exceed {MAX_DIRECTORY_ENTRIES}",
                        )
                        return None
        except OSError:
            self._add("FS002", relative, "directory cannot be enumerated")
            return None
        entries.sort(key=lambda item: item.name)
        return entries

    def _enumerate_tree_anchored(self) -> None:
        """Enumerate with no-follow directory handles on POSIX-like systems."""

        nofollow = os.O_NOFOLLOW
        directory_flag = os.O_DIRECTORY
        state = {"bytes": 0, "directories": 1, "stop": False}

        def walk(directory: int, relative_directory: str, depth: int) -> None:
            if state["stop"]:
                return
            if depth > MAX_DIRECTORY_DEPTH:
                self._add(
                    "LIMIT008",
                    relative_directory,
                    f"directory depth exceeds {MAX_DIRECTORY_DEPTH}",
                )
                state["stop"] = True
                return
            entries = self._bounded_entries(directory, relative_directory)
            if entries is None:
                state["stop"] = True
                return
            for entry in entries:
                if state["stop"]:
                    return
                relative = (
                    entry.name
                    if relative_directory == "."
                    else f"{relative_directory}/{entry.name}"
                )
                try:
                    status = entry.stat(follow_symlinks=False)
                    junction_probe = getattr(entry, "is_junction", None)
                    is_junction = bool(
                        callable(junction_probe) and junction_probe()
                    )
                except OSError:
                    self._add("FS003", relative, "entry cannot be inspected")
                    continue
                if (
                    stat.S_ISLNK(status.st_mode)
                    or is_junction
                    or self._is_reparse_point(status, relative)
                ):
                    self._add(
                        "FS004",
                        relative,
                        "symbolic links and junctions are prohibited",
                    )
                    continue
                if stat.S_ISDIR(status.st_mode):
                    try:
                        child = os.open(
                            entry.name,
                            os.O_RDONLY | directory_flag | nofollow,
                            dir_fd=directory,
                        )
                        child_status = os.fstat(child)
                        if (
                            not stat.S_ISDIR(child_status.st_mode)
                            or self._is_reparse_point(child_status, relative)
                        ):
                            self._add(
                                "FS004",
                                relative,
                                "directory changed to an unsafe entry",
                            )
                            os.close(child)
                            continue
                    except OSError:
                        self._add(
                            "FS004",
                            relative,
                            "directory cannot be opened without following links",
                        )
                        continue
                    state["directories"] += 1
                    if state["directories"] > MAX_DIRECTORIES:
                        self._add(
                            "LIMIT009",
                            ".",
                            f"directory count exceeds {MAX_DIRECTORIES}",
                        )
                        state["stop"] = True
                        os.close(child)
                        return
                    try:
                        walk(child, relative, depth + 1)
                    finally:
                        os.close(child)
                    continue
                if not stat.S_ISREG(status.st_mode):
                    self._add("FS005", relative, "non-regular files are prohibited")
                    continue
                try:
                    descriptor = os.open(
                        entry.name,
                        os.O_RDONLY | nofollow | getattr(os, "O_BINARY", 0),
                        dir_fd=directory,
                    )
                    try:
                        opened_status = os.fstat(descriptor)
                        if (
                            not stat.S_ISREG(opened_status.st_mode)
                            or self._is_reparse_point(opened_status, relative)
                        ):
                            self._add(
                                "FS007",
                                relative,
                                "file changed to a non-regular entry",
                            )
                            continue
                        file_size = opened_status.st_size
                    finally:
                        os.close(descriptor)
                except OSError:
                    self._add(
                        "FS008",
                        relative,
                        "file cannot be opened without following links",
                    )
                    continue
                if len(self.files) >= MAX_FILES:
                    self._add("LIMIT001", ".", f"file count exceeds {MAX_FILES}")
                    continue
                if state["bytes"] + file_size > MAX_TOTAL_BYTES:
                    self._add("LIMIT002", ".", f"tree bytes exceed {MAX_TOTAL_BYTES}")
                    state["stop"] = True
                    return
                self.files[relative] = self.root / PurePosixPath(relative)
                state["bytes"] += file_size

        try:
            root_descriptor = os.open(
                self.root,
                os.O_RDONLY | directory_flag | nofollow,
            )
            try:
                root_status = os.fstat(root_descriptor)
                if (
                    not stat.S_ISDIR(root_status.st_mode)
                    or self._is_reparse_point(root_status, ".")
                ):
                    self._add("FS001", ".", "research root must be a real directory")
                    return
                walk(root_descriptor, ".", 0)
            finally:
                os.close(root_descriptor)
        except OSError:
            self._add("FS001", ".", "research root cannot be opened safely")

    def _enumerate_tree_portable(self) -> None:
        """Fail-closed fallback with per-component and final-handle checks."""

        state = {"bytes": 0, "directories": 1, "stop": False}

        def walk(relative_directory: str, depth: int) -> None:
            if state["stop"]:
                return
            if depth > MAX_DIRECTORY_DEPTH:
                self._add(
                    "LIMIT008",
                    relative_directory,
                    f"directory depth exceeds {MAX_DIRECTORY_DEPTH}",
                )
                state["stop"] = True
                return
            directory = (
                self.root
                if relative_directory == "."
                else self.root / PurePosixPath(relative_directory)
            )
            if not self._portable_directory_is_safe(relative_directory):
                self._add("FS004", relative_directory, "unsafe directory component")
                state["stop"] = True
                return
            entries = self._bounded_entries(directory, relative_directory)
            if entries is None:
                state["stop"] = True
                return
            for entry in entries:
                if state["stop"]:
                    return
                relative = (
                    entry.name
                    if relative_directory == "."
                    else f"{relative_directory}/{entry.name}"
                )
                try:
                    status = entry.stat(follow_symlinks=False)
                    junction_probe = getattr(entry, "is_junction", None)
                    is_junction = bool(
                        callable(junction_probe) and junction_probe()
                    )
                except OSError:
                    self._add("FS003", relative, "entry cannot be inspected")
                    continue
                if (
                    stat.S_ISLNK(status.st_mode)
                    or is_junction
                    or self._is_reparse_point(status, relative)
                ):
                    self._add(
                        "FS004",
                        relative,
                        "symbolic links and junctions are prohibited",
                    )
                    continue
                if stat.S_ISDIR(status.st_mode):
                    state["directories"] += 1
                    if state["directories"] > MAX_DIRECTORIES:
                        self._add(
                            "LIMIT009",
                            ".",
                            f"directory count exceeds {MAX_DIRECTORIES}",
                        )
                        state["stop"] = True
                        return
                    walk(relative, depth + 1)
                    continue
                if not stat.S_ISREG(status.st_mode):
                    self._add("FS005", relative, "non-regular files are prohibited")
                    continue
                descriptor: int | None = None
                try:
                    descriptor = self._open_anchored(
                        relative,
                        os.O_RDONLY | getattr(os, "O_BINARY", 0),
                    )
                    opened_status = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened_status.st_mode)
                        or self._is_reparse_point(opened_status, relative)
                        or not self._descriptor_is_contained(descriptor, relative)
                    ):
                        self._add(
                            "FS007",
                            relative,
                            "file changed to a non-regular or external entry",
                        )
                        continue
                    file_size = opened_status.st_size
                except OSError:
                    self._add(
                        "FS008",
                        relative,
                        "file cannot be opened without following links",
                    )
                    continue
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                if len(self.files) >= MAX_FILES:
                    self._add("LIMIT001", ".", f"file count exceeds {MAX_FILES}")
                    continue
                if state["bytes"] + file_size > MAX_TOTAL_BYTES:
                    self._add("LIMIT002", ".", f"tree bytes exceed {MAX_TOTAL_BYTES}")
                    state["stop"] = True
                    return
                self.files[relative] = self.root / PurePosixPath(relative)
                state["bytes"] += file_size

        walk(".", 0)

    def _portable_directory_is_safe(self, relative: str) -> bool:
        current = self.root
        parts = () if relative == "." else PurePosixPath(relative).parts
        try:
            root_resolved = self.root.resolve(strict=True)
            for component in parts:
                current /= component
                status = current.lstat()
                if (
                    stat.S_ISLNK(status.st_mode)
                    or not stat.S_ISDIR(status.st_mode)
                    or self._is_reparse_point(status, self._relative(current))
                ):
                    return False
            resolved = current.resolve(strict=True)
            return os.path.commonpath((root_resolved, resolved)) == str(root_resolved)
        except (OSError, ValueError):
            return False

    def _is_reparse_point(self, status: os.stat_result, relative: str) -> bool:
        """Reject Windows reparse entries and fail closed without attributes."""

        attributes = getattr(status, "st_file_attributes", None)
        if os.name != "nt":
            return bool(
                attributes is not None
                and attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            )
        if attributes is None:
            self._add(
                "FS009",
                relative,
                "Windows reparse-point safety could not be established",
            )
            return True
        return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)

    def _relative(self, path: Path) -> str:
        try:
            value = path.relative_to(self.root).as_posix()
        except ValueError:
            return "."
        return value or "."

    def _read(self, relative: str) -> bytes | None:
        cached = self.payloads.get(relative)
        if cached is not None:
            return cached
        path = self.files.get(relative)
        if path is None:
            self._add("FS006", relative, "referenced file is missing")
            return None
        maximum = (
            MAX_JSON_BYTES
            if path.suffix.lower() in {".json", ".sarif"}
            else MAX_TEXT_BYTES
        )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        try:
            descriptor = self._open_anchored(relative, flags)
            try:
                status = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(status.st_mode)
                    or self._is_reparse_point(status, relative)
                    or not self._descriptor_is_contained(descriptor, relative)
                ):
                    self._add("FS007", relative, "file changed to a non-regular entry")
                    return None
                chunks: list[bytes] = []
                observed = 0
                while True:
                    chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - observed))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    observed += len(chunk)
                    if observed > maximum:
                        self._add(
                            "LIMIT003",
                            relative,
                            f"file bytes exceed {maximum}",
                        )
                        return None
                payload = b"".join(chunks)
            finally:
                os.close(descriptor)
        except OSError:
            self._add("FS008", relative, "file cannot be read without following links")
            return None
        if self.read_bytes + len(payload) > MAX_TOTAL_BYTES:
            self._add("LIMIT002", ".", f"tree bytes exceed {MAX_TOTAL_BYTES}")
            return None
        self.read_bytes += len(payload)
        self.payloads[relative] = payload
        return payload

    def _open_anchored(self, relative: str, flags: int) -> int:
        """Open beneath the root without following a replaced parent directory.

        POSIX walks no-follow directory handles. Platforms without directory-FD
        support receive a component-by-component reparse check and a final-handle
        check in ``_read``.
        """

        parts = PurePosixPath(relative).parts
        if not parts or any(part in {"", ".", ".."} for part in parts):
            raise OSError("invalid relative path")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if os.open in os.supports_dir_fd and directory_flag and nofollow:
            descriptor = os.open(
                self.root,
                os.O_RDONLY | directory_flag | nofollow,
            )
            try:
                for component in parts[:-1]:
                    child = os.open(
                        component,
                        os.O_RDONLY | directory_flag | nofollow,
                        dir_fd=descriptor,
                    )
                    os.close(descriptor)
                    descriptor = child
                return os.open(
                    parts[-1],
                    flags | nofollow,
                    dir_fd=descriptor,
                )
            finally:
                os.close(descriptor)

        current = self.root
        for component in parts[:-1]:
            current /= component
            status = current.lstat()
            if (
                stat.S_ISLNK(status.st_mode)
                or not stat.S_ISDIR(status.st_mode)
                or self._is_reparse_point(status, self._relative(current))
            ):
                raise OSError("unsafe parent component")
        return os.open(self.root.joinpath(*parts), flags | nofollow)

    def _descriptor_is_contained(self, descriptor: int, relative: str) -> bool:
        """On Windows, bind containment to the opened handle's resolved path."""

        if os.name != "nt":
            return True
        try:
            import ctypes
            import msvcrt
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            final_path = kernel32.GetFinalPathNameByHandleW
            final_path.argtypes = (
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            )
            final_path.restype = wintypes.DWORD
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL

            def resolved_handle_path(handle: int) -> str:
                buffer = ctypes.create_unicode_buffer(32768)
                # VOLUME_NAME_NT avoids drive-letter aliases. Preserve the
                # kernel-returned case because Windows directories may opt in
                # to case-sensitive name lookup.
                copied = final_path(handle, buffer, len(buffer), 0x00000002)
                if copied == 0 or copied >= len(buffer):
                    raise OSError("GetFinalPathNameByHandleW failed")
                value = buffer.value
                if value.startswith("\\\\?\\UNC\\"):
                    value = "\\\\" + value[8:]
                elif value.startswith("\\\\?\\"):
                    value = value[4:]
                return os.path.normpath(value)

            # Compare two kernel-resolved handles. A lexical root can differ
            # from a file handle on hosted runners that use drive mappings;
            # comparing it to the final file path would reject safe files.
            # FILE_FLAG_OPEN_REPARSE_POINT prevents a replaced root from being
            # followed while FILE_FLAG_BACKUP_SEMANTICS permits directory open.
            root_handle = create_file(
                os.fspath(os.path.abspath(self.root)),
                0,
                0x00000001 | 0x00000002 | 0x00000004,
                None,
                3,
                0x02000000 | 0x00200000,
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if root_handle == invalid_handle:
                raise OSError("CreateFileW failed for research root")
            try:
                root = resolved_handle_path(root_handle)
            finally:
                if not close_handle(root_handle):
                    raise OSError("CloseHandle failed for research root")
            target = resolved_handle_path(msvcrt.get_osfhandle(descriptor))
            return self._windows_handle_target_is_descendant(root, target)
        except (AttributeError, ImportError, OSError, ValueError):
            self._add(
                "FS009",
                relative,
                "opened-handle containment could not be established",
            )
            return False

    @staticmethod
    def _windows_handle_target_is_descendant(root: str, target: str) -> bool:
        """Compare normalized NT handle paths without case folding."""

        root_with_boundary = root.rstrip("\\") + "\\"
        return target.startswith(root_with_boundary)

    def _decode_text(self, relative: str, payload: bytes) -> str | None:
        if payload.startswith(b"\xef\xbb\xbf"):
            self._add("TEXT001", relative, "UTF-8 BOM is prohibited")
            return None
        if b"\r" in payload:
            self._add("TEXT002", relative, "CR and CRLF line endings are prohibited")
        if b"\x00" in payload:
            self._add("TEXT003", relative, "NUL bytes are prohibited in text")
            return None
        try:
            return payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            self._add("TEXT004", relative, "text is not strict UTF-8")
            return None

    def _scan_text_and_json(self) -> None:
        for relative in sorted(self.files):
            path = self.files[relative]
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            payload = self._read(relative)
            if payload is None:
                continue
            text = self._decode_text(relative, payload)
            if text is None:
                continue
            if path.suffix.lower() not in {".json", ".sarif"}:
                continue
            if not payload.endswith(b"\n"):
                self._add("JSON001", relative, "JSON must end with one LF")
            document = self._parse_json(relative, text)
            if document is not None:
                self.json_documents[relative] = document

    def _parse_json(self, relative: str, text: str) -> object | None:
        def reject_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise DuplicateKeyError(key)
                result[key] = value
            return result

        def reject_constant(value: str) -> object:
            raise ValueError(f"non-standard numeric constant {value}")

        if not self._precheck_json_depth(relative, text):
            return None
        try:
            document = json.loads(
                text,
                object_pairs_hook=reject_duplicate,
                parse_constant=reject_constant,
            )
        except DuplicateKeyError as error:
            self._add("JSON002", relative, f"duplicate object key {error.args[0]!r}")
            return None
        except RecursionError:
            self._add(
                "LIMIT005",
                relative,
                f"JSON depth exceeds {MAX_JSON_DEPTH}",
            )
            return None
        except (json.JSONDecodeError, ValueError):
            self._add("JSON003", relative, "invalid strict JSON")
            return None

        nodes = 0
        stack: list[tuple[object, int]] = [(document, 1)]
        while stack:
            value, depth = stack.pop()
            nodes += 1
            if nodes > MAX_JSON_NODES:
                self._add(
                    "LIMIT004",
                    relative,
                    f"JSON nodes exceed {MAX_JSON_NODES}",
                )
                return None
            if depth > MAX_JSON_DEPTH:
                self._add(
                    "LIMIT005",
                    relative,
                    f"JSON depth exceeds {MAX_JSON_DEPTH}",
                )
                return None
            if isinstance(value, dict):
                stack.extend((child, depth + 1) for child in value.values())
            elif isinstance(value, list):
                stack.extend((child, depth + 1) for child in value)
        return document

    def _precheck_json_depth(self, relative: str, text: str) -> bool:
        """Bound structural nesting before CPython materializes a JSON tree."""

        depth = 0
        in_string = False
        escaped = False
        for character in text:
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    self._add(
                        "LIMIT005",
                        relative,
                        f"JSON depth exceeds {MAX_JSON_DEPTH}",
                    )
                    return False
            elif character in "]}":
                depth = max(0, depth - 1)
        return True

    def _safe_relative(self, value: object, owner: str) -> str | None:
        if not _is_canonical_relative_path(value):
            self._add("PATH001", owner, "manifest path is not portable")
            return None
        assert isinstance(value, str)
        path = PurePosixPath(value)
        relative = path.as_posix()
        if relative not in self.files and not any(
            candidate == relative or candidate.startswith(relative + "/")
            for candidate in self.files
        ):
            self._add("PATH002", owner, f"referenced path is missing: {relative}")
            return None
        return relative

    def _scan_integrity(self, manifest: Mapping[str, object]) -> None:
        integrity = manifest.get("integrity")
        if not isinstance(integrity, dict) or integrity.get("algorithm") != "sha256":
            self._add("INTEGRITY001", "manifest.json", "invalid integrity contract")
            return
        entries = integrity.get("files")
        if not isinstance(entries, list) or len(entries) > MAX_FILES:
            self._add("INTEGRITY002", "manifest.json", "invalid integrity file list")
            return
        observed: dict[str, str] = {}
        listed_order: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict):
                self._add("INTEGRITY003", "manifest.json", "integrity entry is not an object")
                continue
            relative = entry.get("path")
            digest = entry.get("sha256")
            if not isinstance(relative, str) or not isinstance(digest, str):
                self._add("INTEGRITY003", "manifest.json", "integrity entry is incomplete")
                continue
            if relative == "manifest.json":
                self._add("INTEGRITY004", "manifest.json", "manifest must not hash itself")
                continue
            if relative in observed:
                self._add("INTEGRITY005", "manifest.json", f"duplicate integrity path: {relative}")
                continue
            observed[relative] = digest
            listed_order.append(relative)
        if listed_order != sorted(listed_order):
            self._add("INTEGRITY006", "manifest.json", "integrity paths are not ordinal-sorted")
        expected_paths = {
            relative
            for relative in self.files
            if relative != "manifest.json" and not relative.startswith("expected/")
        }
        if set(observed) != expected_paths:
            missing = sorted(expected_paths - set(observed))
            extra = sorted(set(observed) - expected_paths)
            detail = "integrity coverage differs"
            if missing:
                detail += f"; first missing={missing[0]}"
            if extra:
                detail += f"; first extra={extra[0]}"
            self._add("INTEGRITY007", "manifest.json", detail)
        for relative in sorted(set(observed) & expected_paths):
            payload = self._read(relative)
            if payload is None:
                continue
            actual = hashlib.sha256(payload).hexdigest()
            if not re.fullmatch(r"[0-9a-f]{64}", observed[relative]) or actual != observed[relative]:
                self._add("INTEGRITY008", relative, "integrity SHA-256 does not match bytes")

    def _scan_expected_checksums(self) -> None:
        checksum_path = "expected/checksums.sha256"
        expected_files = sorted(
            relative
            for relative in self.files
            if relative.startswith("expected/") and relative != checksum_path
        )
        if not expected_files:
            if checksum_path in self.files:
                self._add(
                    "EXPECTED001",
                    checksum_path,
                    "checksum manifest exists without expected outputs",
                )
            return
        payload = self._read(checksum_path)
        if payload is None:
            self._add(
                "EXPECTED002",
                checksum_path,
                "expected-output checksum manifest is required",
            )
            return
        text = self._decode_text(checksum_path, payload)
        if text is None:
            return
        if not text.endswith("\n"):
            self._add("EXPECTED003", checksum_path, "checksum manifest must end with LF")
            return
        observed: dict[str, str] = {}
        order: list[str] = []
        for line in text.splitlines():
            match = re.fullmatch(
                r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)",
                line,
            )
            if match is None:
                self._add("EXPECTED004", checksum_path, "invalid checksum entry")
                continue
            nested = match.group(2)
            if nested in observed:
                self._add("EXPECTED005", checksum_path, f"duplicate checksum path: {nested}")
                continue
            if PurePosixPath(nested).is_absolute() or ".." in PurePosixPath(nested).parts:
                self._add("EXPECTED004", checksum_path, "non-relative checksum path")
                continue
            observed[nested] = match.group(1)
            order.append(nested)
        if order != sorted(order):
            self._add("EXPECTED006", checksum_path, "checksum paths are not ordinal-sorted")
        expected_nested = {
            relative[len("expected/") :]
            for relative in expected_files
        }
        if set(observed) != expected_nested:
            self._add(
                "EXPECTED007",
                checksum_path,
                "checksum coverage differs from expected outputs",
            )
        for nested in sorted(set(observed) & expected_nested):
            relative = f"expected/{nested}"
            file_payload = self._read(relative)
            if file_payload is None:
                continue
            if hashlib.sha256(file_payload).hexdigest() != observed[nested]:
                self._add("EXPECTED008", relative, "expected-output checksum does not match")

    def _validate_manifest_contract(self, manifest: Mapping[str, object]) -> None:
        """Mirror the closed manifest schema without a runtime dependency."""

        valid = set(manifest) == {
            "schemaVersion",
            "corpusId",
            "producer",
            "families",
            "contamination",
            "integrity",
        }
        valid &= (
            manifest.get("schemaVersion") == "1"
            and manifest.get("corpusId") == "pmd-sparse-research"
        )

        producer = manifest.get("producer")
        producer_keys = {
            "family",
            "name",
            "version",
            "sourceCommit",
            "projectUrl",
            "releaseUrl",
            "license",
            "archive",
            "helpSha256",
            "capture",
        }
        valid &= isinstance(producer, dict) and set(producer) == producer_keys
        if isinstance(producer, dict):
            valid &= producer.get("family") == "pmd"
            valid &= producer.get("name") == "PMD"
            valid &= producer.get("version") == "7.26.0"
            valid &= producer.get("sourceCommit") == PMD_SOURCE_COMMIT
            valid &= producer.get("projectUrl") == PMD_PROJECT_URL
            valid &= producer.get("releaseUrl") == PMD_RELEASE_URL
            valid &= producer.get("helpSha256") == (
                "babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91"
            )
            valid &= producer.get("license") == {
                "identifier": "LicenseRef-PMD-BSD-Style",
                "name": "PMD BSD-style license",
                "url": PMD_LICENSE_URL,
            }
            valid &= producer.get("archive") == {
                "url": (
                    "https://github.com/pmd/pmd/releases/download/"
                    "pmd_releases/7.26.0/pmd-dist-7.26.0-bin.zip"
                ),
                "sizeBytes": 73_646_044,
                "sha256": (
                    "9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
                ),
            }
            capture = producer.get("capture")
            capture_keys = {
                "sourceHeadSha",
                "workflow",
                "runner",
                "runtime",
                "contract",
                "captureCommand",
                "downloadCommand",
            }
            valid &= isinstance(capture, dict) and set(capture) == capture_keys
            if isinstance(capture, dict):
                source_head = capture.get("sourceHeadSha")
                valid &= (
                    isinstance(source_head, str)
                    and re.fullmatch(r"[0-9a-f]{40}", source_head) is not None
                )
                workflow = capture.get("workflow")
                valid &= isinstance(workflow, dict) and set(workflow) == {
                    "runId",
                    "artifactId",
                    "artifactName",
                    "artifactDigest",
                }
                if isinstance(workflow, dict):
                    valid &= all(
                        type(workflow.get(key)) is int
                        and 1 <= workflow[key] <= 9_007_199_254_740_991
                        for key in ("runId", "artifactId")
                    )
                    artifact_name = workflow.get("artifactName")
                    valid &= (
                        isinstance(artifact_name, str)
                        and re.fullmatch(
                            r"sparse-sarif-pmd-(?:bootstrap|capture)-[0-9a-f]{40}",
                            artifact_name,
                        )
                        is not None
                        and isinstance(source_head, str)
                        and artifact_name.endswith(source_head)
                    )
                    valid &= (
                        isinstance(workflow.get("artifactDigest"), str)
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            workflow["artifactDigest"],
                        )
                        is not None
                    )
                valid &= capture.get("runner") == {
                    "label": "ubuntu-24.04",
                    "imageOS": "ubuntu24",
                    "imageVersion": (
                        capture.get("runner", {}).get("imageVersion")
                        if isinstance(capture.get("runner"), dict)
                        else None
                    ),
                    "operatingSystem": "Linux",
                    "architecture": "x86_64",
                }
                runner = capture.get("runner")
                valid &= (
                    isinstance(runner, dict)
                    and isinstance(runner.get("imageVersion"), str)
                    and re.fullmatch(
                        r"[0-9]{8}\.[0-9]+\.[0-9]+",
                        runner["imageVersion"],
                    )
                    is not None
                )
                valid &= capture.get("runtime") == {
                    "pythonVersion": "3.12.13",
                    "javaDistribution": "Eclipse Temurin",
                    "javaVendor": "Eclipse Adoptium",
                    "javaVersion": "17.0.19+10",
                }
                contract = capture.get("contract")
                valid &= (
                    isinstance(contract, dict)
                    and set(contract) == {"version", "sha256"}
                    and contract.get("version") == CAPTURE_CONTRACT_VERSION
                    and isinstance(contract.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", contract["sha256"])
                    is not None
                )
                valid &= capture.get("captureCommand") == list(CAPTURE_COMMAND)
                valid &= capture.get("downloadCommand") == list(DOWNLOAD_COMMAND)

        families = manifest.get("families")
        valid &= isinstance(families, list) and 2 <= len(families) <= 16
        family_ids: list[str] = []
        if isinstance(families, list):
            for family in families:
                if not isinstance(family, dict) or set(family) != {
                    "id",
                    "labelsPath",
                    "rulesetPath",
                    "baseline",
                    "candidate",
                }:
                    valid = False
                    continue
                family_id = family.get("id")
                if not isinstance(family_id, str):
                    valid = False
                    continue
                family_ids.append(family_id)
                valid &= re.fullmatch(
                    r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*",
                    family_id,
                ) is not None
                valid &= family.get("labelsPath") == f"cases/{family_id}/labels.json"
                valid &= family.get("rulesetPath") == f"cases/{family_id}/pmd-ruleset.xml"
                for side_name in ("baseline", "candidate"):
                    side = family.get(side_name)
                    valid &= isinstance(side, dict) and set(side) == {
                        "sourceRoot",
                        "sarifPath",
                        "projectionAuditPath",
                        "sourceTreeSha256",
                        "rawCaptureSha256",
                        "rawCaptureBytes",
                        "projectedSarifSha256",
                        "projectedSarifBytes",
                        "projectionAuditSha256",
                        "resultCount",
                    }
                    if not isinstance(side, dict):
                        continue
                    valid &= side.get("sourceRoot") == (
                        f"cases/{family_id}/{side_name}/source"
                    )
                    valid &= side.get("sarifPath") == (
                        f"cases/{family_id}/{side_name}.sarif"
                    )
                    valid &= side.get("projectionAuditPath") == (
                        "capture-evidence/projection-audits/"
                        f"{family_id}/{side_name}.json"
                    )
                    valid &= all(
                        isinstance(side.get(key), str)
                        and re.fullmatch(r"[0-9a-f]{64}", side[key]) is not None
                        for key in (
                            "sourceTreeSha256",
                            "rawCaptureSha256",
                            "projectedSarifSha256",
                            "projectionAuditSha256",
                        )
                    )
                    valid &= all(
                        type(side.get(key)) is int
                        and 1 <= side[key] <= 16 * 1024 * 1024
                        for key in ("rawCaptureBytes", "projectedSarifBytes")
                    )
                    valid &= (
                        type(side.get("resultCount")) is int
                        and 1 <= side["resultCount"] <= MAX_RESULTS
                    )
        valid &= family_ids == sorted(set(family_ids))

        contamination = manifest.get("contamination")
        valid &= isinstance(contamination, dict) and set(contamination) == {
            "scannerPath",
            "scannerSha256",
            "policyVersion",
        }
        if isinstance(contamination, dict):
            valid &= contamination.get("scannerPath") == "tools/scan_contamination.py"
            valid &= contamination.get("policyVersion") == POLICY_VERSION
            valid &= (
                isinstance(contamination.get("scannerSha256"), str)
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    contamination["scannerSha256"],
                )
                is not None
            )
        integrity = manifest.get("integrity")
        valid &= isinstance(integrity, dict) and set(integrity) == {
            "algorithm",
            "files",
        }
        if isinstance(integrity, dict):
            valid &= integrity.get("algorithm") == "sha256"
            entries = integrity.get("files")
            valid &= isinstance(entries, list) and 1 <= len(entries) <= MAX_FILES
            if isinstance(entries, list):
                valid &= all(
                    isinstance(entry, dict)
                    and set(entry) == {"path", "sha256"}
                    and _is_canonical_relative_path(entry.get("path"))
                    and entry.get("path") != "manifest.json"
                    and not str(entry.get("path")).startswith("expected/")
                    and isinstance(entry.get("sha256"), str)
                    and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])
                    is not None
                    for entry in entries
                )
        if not valid:
            self._add(
                "MANIFEST010",
                "manifest.json",
                "manifest does not satisfy the exact sparse-SARIF schema contract",
            )

    def _scan_manifest(self, manifest: Mapping[str, object]) -> None:
        self._validate_manifest_contract(manifest)
        contamination = manifest.get("contamination")
        if not isinstance(contamination, dict) or contamination.get("policyVersion") != POLICY_VERSION:
            self._add("POLICY001", "manifest.json", "contamination policy version is not fixed")
        elif contamination.get("scannerPath") != "tools/scan_contamination.py":
            self._add(
                "POLICY002",
                "manifest.json",
                "scannerPath is not the canonical contamination scanner",
            )
        else:
            scanner_payload = self._read("tools/scan_contamination.py")
            scanner_sha256 = contamination.get("scannerSha256")
            if (
                scanner_payload is None
                or not isinstance(scanner_sha256, str)
                or hashlib.sha256(scanner_payload).hexdigest() != scanner_sha256
            ):
                self._add(
                    "POLICY003",
                    "manifest.json",
                    "scanner policy hash is missing or differs from scanner bytes",
                )
            integrity = manifest.get("integrity")
            entries = integrity.get("files") if isinstance(integrity, dict) else None
            bound = [
                entry.get("sha256")
                for entry in entries
                if isinstance(entries, list)
                and isinstance(entry, dict)
                and entry.get("path") == "tools/scan_contamination.py"
            ] if isinstance(entries, list) else []
            if bound != [scanner_sha256]:
                self._add(
                    "POLICY004",
                    "manifest.json",
                    "scanner policy hash is not uniquely bound by integrity",
                )

        producer = manifest.get("producer")
        if not isinstance(producer, dict) or producer.get("family") != "pmd":
            self._add("MANIFEST002", "manifest.json", "producer family must be pmd")
        capture = producer.get("capture") if isinstance(producer, dict) else None
        contract = capture.get("contract") if isinstance(capture, dict) else None
        capture_contract_sha256 = (
            contract.get("sha256") if isinstance(contract, dict) else None
        )
        families = manifest.get("families")
        if not isinstance(families, list) or not 2 <= len(families) <= 16:
            self._add("MANIFEST003", "manifest.json", "families must contain 2 through 16 entries")
            return
        family_ids: set[str] = set()
        all_label_tokens: set[str] = set()
        family_records: list[tuple[Mapping[str, object], Mapping[str, object], str]] = []
        for index, value in enumerate(families):
            owner = f"manifest.json#families/{index}"
            if not isinstance(value, dict):
                self._add("MANIFEST004", owner, "family is not an object")
                continue
            family_id = value.get("id")
            if not isinstance(family_id, str) or family_id in family_ids:
                self._add("MANIFEST005", owner, "family id is missing or duplicated")
                continue
            family_ids.add(family_id)
            labels_path = self._safe_relative(value.get("labelsPath"), owner)
            self._safe_relative(value.get("rulesetPath"), owner)
            if labels_path is None:
                continue
            labels = self.json_documents.get(labels_path)
            if not isinstance(labels, dict):
                self._add("LABEL001", labels_path, "labels are missing or invalid")
                continue
            self._validate_labels_contract(labels, labels_path)
            if labels.get("familyId") != family_id or labels.get("producerFamily") != "pmd":
                self._add("LABEL002", labels_path, "labels do not identify their manifest family")
            tokens = self._label_tokens(labels, labels_path)
            all_label_tokens.update(tokens)
            family_records.append((value, labels, labels_path))

        if len(all_label_tokens) > MAX_LABEL_TOKENS:
            self._add("LIMIT006", "manifest.json", f"label tokens exceed {MAX_LABEL_TOKENS}")
            all_label_tokens = set(sorted(all_label_tokens)[:MAX_LABEL_TOKENS])
        for family, labels, labels_path in family_records:
            self._scan_family(
                family,
                labels,
                labels_path,
                all_label_tokens,
                capture_contract_sha256,
            )

        expected_prefix = "expected/"
        for relative, document in sorted(self.json_documents.items()):
            if relative.startswith(expected_prefix):
                self._scan_environmental_json(relative, document)
                if (
                    isinstance(document, dict)
                    and {"fixedGates", "variants", "selectedVariant", "decision"}
                    <= set(document)
                ):
                    self._scan_experiment_report(relative, document)

    def _label_tokens(self, labels: Mapping[str, object], labels_path: str) -> set[str]:
        tokens: set[str] = set()
        ids: set[str] = set()
        for category in ("relationships", "new", "resolved", "ambiguities"):
            entries = labels.get(category)
            if not isinstance(entries, list):
                self._add("LABEL003", labels_path, f"{category} is not an array")
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    self._add("LABEL004", labels_path, f"{category} contains a non-object")
                    continue
                label_id = entry.get("id")
                if not isinstance(label_id, str) or not label_id:
                    self._add("LABEL005", labels_path, f"{category} entry has no id")
                elif label_id in ids:
                    self._add("LABEL006", labels_path, f"duplicate label id: {label_id}")
                else:
                    ids.add(label_id)
                    tokens.add(label_id.casefold())
                    self.label_ids[label_id.casefold()] = hashlib.sha256(
                        label_id.casefold().encode("utf-8")
                    ).hexdigest()[:16]
                    components = re.findall(r"[a-z0-9]+", label_id.casefold())
                    normalized = "".join(components)
                    if (
                        len(components) >= 3
                        and len(normalized) >= MIN_NORMALIZED_LABEL_ID_LENGTH
                    ):
                        self.normalized_label_ids[normalized] = hashlib.sha256(
                            label_id.casefold().encode("utf-8")
                        ).hexdigest()[:16]
                proof = entry.get("sourceTransformation")
                if isinstance(proof, dict):
                    kind = proof.get("kind")
                    description = proof.get("description")
                    if isinstance(kind, str) and ("-" in kind or "_" in kind):
                        tokens.add(kind.casefold())
                    if isinstance(description, str):
                        phrase = " ".join(description.split()).casefold()
                        if len(phrase) >= 12:
                            tokens.add(phrase)
                    for key, value in proof.items():
                        if key.lower().endswith("sha256") and isinstance(value, str):
                            tokens.add(value.casefold())
        self._scan_result_index_ground_truth(labels, labels_path)
        return tokens

    def _validate_labels_contract(
        self,
        labels: Mapping[str, object],
        labels_path: str,
    ) -> None:
        """Validate the checked-in labels schema without a runtime dependency."""

        valid = True
        top_keys = {
            "schemaVersion",
            "familyId",
            "producerFamily",
            "ruleId",
            "baselineSarif",
            "candidateSarif",
            "relationships",
            "new",
            "resolved",
            "ambiguities",
        }
        stable_id = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
        if set(labels) != top_keys:
            valid = False
        if (
            labels.get("schemaVersion") != "1"
            or labels.get("producerFamily") != "pmd"
            or labels.get("ruleId") != "AvoidPrintStackTrace"
        ):
            valid = False
        family_id = labels.get("familyId")
        if (
            not isinstance(family_id, str)
            or not 3 <= len(family_id) <= 64
            or stable_id.fullmatch(family_id) is None
        ):
            valid = False
        if not all(
            _is_canonical_relative_path(labels.get(key))
            for key in ("baselineSarif", "candidateSarif")
        ):
            valid = False

        def valid_selector(value: object) -> bool:
            if not isinstance(value, dict) or set(value) != {
                "ruleId",
                "artifactUri",
                "region",
                "message",
            }:
                return False
            message = value.get("message")
            region = value.get("region")
            if (
                value.get("ruleId") != "AvoidPrintStackTrace"
                or not _is_canonical_relative_path(value.get("artifactUri"))
                or not isinstance(message, str)
                or not 1 <= len(message) <= 4096
                or not isinstance(region, dict)
                or set(region)
                != {"startLine", "startColumn", "endLine", "endColumn"}
            ):
                return False
            limits = {
                "startLine": 10_000_000,
                "startColumn": 1_000_000,
                "endLine": 10_000_000,
                "endColumn": 1_000_000,
            }
            return all(
                type(region.get(key)) is int and 1 <= region[key] <= maximum
                for key, maximum in limits.items()
            ) and _region_is_ordered(region, tuple(limits))

        def valid_proof(
            value: object,
            required_sides: frozenset[str],
        ) -> bool:
            if not isinstance(value, dict):
                return False
            allowed = {
                "kind",
                "description",
                "baselineSourcePath",
                "candidateSourcePath",
                "baselineFileSha256",
                "candidateFileSha256",
            }
            if not {"kind", "description"} <= set(value) or not set(value) <= allowed:
                return False
            kind = value.get("kind")
            description = value.get("description")
            if (
                not isinstance(kind, str)
                or not 1 <= len(kind) <= 64
                or stable_id.fullmatch(kind) is None
                or not isinstance(description, str)
                or not 1 <= len(description) <= 2048
            ):
                return False
            for side_name in ("baseline", "candidate"):
                path_key = f"{side_name}SourcePath"
                hash_key = f"{side_name}FileSha256"
                path_present = path_key in value
                hash_present = hash_key in value
                if path_present != hash_present or (
                    side_name in required_sides and not path_present
                ):
                    return False
                if path_key in value and not _is_canonical_relative_path(value[path_key]):
                    return False
                if hash_key in value and (
                    path_key not in value
                    or not isinstance(value[hash_key], str)
                    or re.fullmatch(r"[0-9a-f]{64}", value[hash_key]) is None
                ):
                    return False
            return True

        entry_contracts = {
            "relationships": (
                10_000,
                {"id", "expectedClassification", "baseline", "candidate", "sourceTransformation"},
                {"unchanged", "moved", "modified"},
                ("baseline", "candidate"),
                frozenset({"baseline", "candidate"}),
            ),
            "new": (
                10_000,
                {"id", "expectedClassification", "candidate", "sourceTransformation"},
                {"new"},
                ("candidate",),
                frozenset({"candidate"}),
            ),
            "resolved": (
                10_000,
                {"id", "expectedClassification", "baseline", "sourceTransformation"},
                {"resolved"},
                ("baseline",),
                frozenset({"baseline"}),
            ),
        }
        for category, contract in entry_contracts.items():
            maximum, keys, classifications, selector_keys, required_sides = contract
            entries = labels.get(category)
            if not isinstance(entries, list) or not 1 <= len(entries) <= maximum:
                valid = False
                continue
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != keys:
                    valid = False
                    continue
                entry_id = entry.get("id")
                if (
                    not isinstance(entry_id, str)
                    or not 3 <= len(entry_id) <= 64
                    or stable_id.fullmatch(entry_id) is None
                    or entry.get("expectedClassification") not in classifications
                    or not valid_proof(
                        entry.get("sourceTransformation"),
                        required_sides,
                    )
                    or any(not valid_selector(entry.get(key)) for key in selector_keys)
                ):
                    valid = False

        ambiguities = labels.get("ambiguities")
        if not isinstance(ambiguities, list) or not 1 <= len(ambiguities) <= 1000:
            valid = False
        else:
            for ambiguity in ambiguities:
                keys = {
                    "id",
                    "shape",
                    "baseline",
                    "candidate",
                    "expected",
                    "sourceTransformation",
                }
                if not isinstance(ambiguity, dict) or set(ambiguity) != keys:
                    valid = False
                    continue
                entry_id = ambiguity.get("id")
                baseline = ambiguity.get("baseline")
                candidate = ambiguity.get("candidate")
                shape = ambiguity.get("shape")
                if (
                    not isinstance(entry_id, str)
                    or not 3 <= len(entry_id) <= 64
                    or stable_id.fullmatch(entry_id) is None
                    or shape not in {"one-to-many", "many-to-one", "many-to-many"}
                    or ambiguity.get("expected") != "refuse"
                    or not valid_proof(
                        ambiguity.get("sourceTransformation"),
                        frozenset({"baseline", "candidate"}),
                    )
                    or not isinstance(baseline, list)
                    or not isinstance(candidate, list)
                    or not 1 <= len(baseline) <= 100
                    or not 1 <= len(candidate) <= 100
                    or any(not valid_selector(item) for item in baseline + candidate)
                    or len({json.dumps(item, sort_keys=True) for item in baseline})
                    != len(baseline)
                    or len({json.dumps(item, sort_keys=True) for item in candidate})
                    != len(candidate)
                    or not (
                        (shape == "one-to-many" and len(baseline) == 1 and len(candidate) >= 2)
                        or (shape == "many-to-one" and len(baseline) >= 2 and len(candidate) == 1)
                        or (shape == "many-to-many" and len(baseline) >= 2 and len(candidate) >= 2)
                    )
                ):
                    valid = False
        if not valid:
            self._add(
                "LABEL018",
                labels_path,
                "labels do not satisfy the exact sparse-SARIF labels schema contract",
            )

    def _scan_result_index_ground_truth(self, value: object, labels_path: str) -> None:
        stack: list[object] = [value]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                for key, child in current.items():
                    normalized = re.sub(r"[-_]", "", key)
                    if RESULT_INDEX_KEY_PATTERN.fullmatch(normalized) or normalized.lower() == "index":
                        self._add("LABEL007", labels_path, f"result-index ground truth key: {key}")
                    stack.append(child)
            elif isinstance(current, list):
                stack.extend(current)
            elif isinstance(current, str) and RESULT_INDEX_VALUE_PATTERN.search(current):
                self._add("LABEL008", labels_path, "result-index ground truth value is prohibited")

    def _scan_projection_audit(
        self,
        family_id: str,
        side_name: str,
        side: Mapping[str, object],
        source_root: str,
        sarif_path: str,
        sarif: object,
        results: Sequence[object],
        capture_contract_sha256: object,
    ) -> None:
        """Validate and cross-bind one committed URI-projection audit."""

        expected_path = (
            "capture-evidence/projection-audits/"
            f"{family_id}/{side_name}.json"
        )
        audit_path = self._safe_relative(
            side.get("projectionAuditPath"),
            "manifest.json",
        )
        if audit_path != expected_path:
            self._add(
                "AUDIT002",
                "manifest.json",
                f"{family_id}/{side_name} projection audit path is not canonical",
            )
        if audit_path is None:
            return
        audit_payload = self._read(audit_path)
        if audit_payload is None:
            return
        if (
            not isinstance(side.get("projectionAuditSha256"), str)
            or hashlib.sha256(audit_payload).hexdigest()
            != side.get("projectionAuditSha256")
        ):
            self._add("AUDIT002", audit_path, "projection audit SHA-256 differs")
        audit = self.json_documents.get(audit_path)
        if not isinstance(audit, dict):
            self._add("AUDIT001", audit_path, "projection audit is not an object")
            return
        self._scan_environmental_json(audit_path, audit)
        self._scan_sarif_ground_truth(audit_path, audit)

        raw = audit.get("rawSarif")
        projected = audit.get("projectedSarif")
        changes = audit.get("changes")
        shape_is_valid = (
            set(audit)
            == {
                "schemaVersion",
                "algorithmVersion",
                "captureContractSha256",
                "familyId",
                "side",
                "logicalSourceRoot",
                "rawSarif",
                "projectedSarif",
                "changes",
            }
            and audit.get("schemaVersion") == "1"
            and audit.get("algorithmVersion") == PROJECTION_ALGORITHM_VERSION
            and isinstance(audit.get("captureContractSha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", audit["captureContractSha256"])
            is not None
            and isinstance(audit.get("familyId"), str)
            and isinstance(audit.get("side"), str)
            and _is_canonical_relative_path(audit.get("logicalSourceRoot"))
            and isinstance(raw, dict)
            and set(raw) == {"bytes", "sha256"}
            and type(raw.get("bytes")) is int
            and 1 <= raw["bytes"] <= 16 * 1024 * 1024
            and isinstance(raw.get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", raw["sha256"]) is not None
            and isinstance(projected, dict)
            and set(projected) == {"bytes", "sha256", "resultCount"}
            and type(projected.get("bytes")) is int
            and 1 <= projected["bytes"] <= 16 * 1024 * 1024
            and isinstance(projected.get("sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", projected["sha256"])
            is not None
            and type(projected.get("resultCount")) is int
            and 1 <= projected["resultCount"] <= MAX_RESULTS
            and isinstance(changes, list)
            and 1 <= len(changes) <= MAX_RESULTS
        )
        if isinstance(changes, list):
            for change in changes:
                shape_is_valid &= (
                    isinstance(change, dict)
                    and set(change)
                    == {
                        "kind",
                        "pointer",
                        "originalValueSha256",
                        "projectedValue",
                    }
                    and change.get("kind")
                    == "checkout-file-uri-prefix-removal"
                    and isinstance(change.get("pointer"), str)
                    and re.fullmatch(
                        r"/runs/0/results/(?:0|[1-9][0-9]*)/locations/0/"
                        r"physicalLocation/artifactLocation/uri",
                        change["pointer"],
                    )
                    is not None
                    and isinstance(change.get("originalValueSha256"), str)
                    and re.fullmatch(
                        r"[0-9a-f]{64}",
                        change["originalValueSha256"],
                    )
                    is not None
                    and _is_canonical_relative_path(change.get("projectedValue"))
                )
        if not shape_is_valid:
            self._add(
                "AUDIT001",
                audit_path,
                "projection audit does not satisfy its exact schema contract",
            )

        if (
            audit.get("familyId") != family_id
            or audit.get("side") != side_name
            or audit.get("logicalSourceRoot") != source_root
        ):
            self._add(
                "AUDIT003",
                audit_path,
                "projection audit family, side, or logical root differs",
            )
        if audit.get("captureContractSha256") != capture_contract_sha256:
            self._add(
                "AUDIT004",
                audit_path,
                "projection audit capture contract differs from manifest",
            )
        if not isinstance(raw, dict) or (
            raw.get("sha256") != side.get("rawCaptureSha256")
            or raw.get("bytes") != side.get("rawCaptureBytes")
        ):
            self._add(
                "AUDIT005",
                audit_path,
                "projection audit raw evidence differs from manifest",
            )

        sarif_payload = self._read(sarif_path)
        actual_projected_sha256 = (
            hashlib.sha256(sarif_payload).hexdigest()
            if sarif_payload is not None
            else None
        )
        if not isinstance(projected, dict) or (
            projected.get("sha256") != side.get("projectedSarifSha256")
            or projected.get("sha256") != actual_projected_sha256
            or projected.get("bytes") != side.get("projectedSarifBytes")
            or sarif_payload is None
            or projected.get("bytes") != len(sarif_payload)
            or projected.get("resultCount") != side.get("resultCount")
            or projected.get("resultCount") != len(results)
        ):
            self._add(
                "AUDIT006",
                audit_path,
                "projection audit projected evidence differs from manifest or SARIF",
            )

        expected_pointers = [
            f"/runs/0/results/{index}/locations/0/physicalLocation/"
            "artifactLocation/uri"
            for index in range(len(results))
        ]
        observed_pointers: list[object] = []
        observed_values: list[object] = []
        if isinstance(changes, list):
            observed_pointers = [
                change.get("pointer") if isinstance(change, dict) else None
                for change in changes
            ]
            observed_values = [
                change.get("projectedValue") if isinstance(change, dict) else None
                for change in changes
            ]
        projected_values: list[object] = []
        runs = sarif.get("runs") if isinstance(sarif, dict) else None
        run_results: object = None
        if isinstance(runs, list) and len(runs) == 1 and isinstance(runs[0], dict):
            run_results = runs[0].get("results")
        if isinstance(run_results, list):
            for result in run_results:
                try:
                    projected_values.append(
                        result["locations"][0]["physicalLocation"]
                        ["artifactLocation"]["uri"]
                    )
                except (KeyError, IndexError, TypeError):
                    projected_values.append(None)
        pointers_are_exact = (
            isinstance(changes, list)
            and len(changes) == len(results)
            and observed_pointers == expected_pointers
            and len(set(observed_pointers)) == len(observed_pointers)
            and isinstance(run_results, list)
            and len(run_results) == len(results)
            and observed_values == projected_values
            and all(
                isinstance(result, dict)
                and isinstance(result.get("locations"), list)
                and len(result["locations"]) == 1
                for result in run_results
            )
        )
        if not pointers_are_exact:
            self._add(
                "AUDIT007",
                audit_path,
                "projection changes do not exactly cover ordered primary artifact URIs",
            )

    def _scan_family(
        self,
        family: Mapping[str, object],
        labels: Mapping[str, object],
        labels_path: str,
        label_tokens: set[str],
        capture_contract_sha256: object,
    ) -> None:
        sides: dict[str, tuple[Mapping[str, object], str, str, object]] = {}
        family_id = family.get("id")
        family_prefix = (
            f"cases/{family_id}/" if isinstance(family_id, str) else ""
        )
        for side_name in ("baseline", "candidate"):
            side = family.get(side_name)
            if not isinstance(side, dict):
                self._add("MANIFEST006", "manifest.json", f"{side_name} side is missing")
                continue
            source_root = self._safe_relative(side.get("sourceRoot"), "manifest.json")
            sarif_path = self._safe_relative(side.get("sarifPath"), "manifest.json")
            if source_root is None or sarif_path is None:
                continue
            if (
                not family_prefix
                or not source_root.startswith(family_prefix)
                or not sarif_path.startswith(family_prefix)
            ):
                self._add(
                    "MANIFEST007",
                    "manifest.json",
                    f"{side_name} inputs are not contained in their family directory",
                )
                continue
            source_files = sorted(
                relative
                for relative in self.files
                if relative.startswith(source_root + "/")
            )
            if not source_files:
                self._add("SOURCE001", source_root, "source root contains no files")
            self._verify_side_hashes(side, source_root, source_files, sarif_path)
            for relative in source_files:
                self._scan_source(relative, label_tokens)
            sarif = self.json_documents.get(sarif_path)
            if sarif is None:
                self._add("SARIF001", sarif_path, "SARIF is missing or invalid")
                continue
            results = self._sarif_results(sarif_path, sarif)
            expected_count = side.get("resultCount")
            if not isinstance(expected_count, int) or expected_count != len(results):
                self._add("SARIF002", sarif_path, "manifest result count does not match SARIF")
            self._scan_sparse_results(sarif_path, results)
            self._scan_sarif_ground_truth(sarif_path, sarif)
            self._scan_environmental_json(sarif_path, sarif)
            if isinstance(family_id, str):
                self._scan_projection_audit(
                    family_id,
                    side_name,
                    side,
                    source_root,
                    sarif_path,
                    sarif,
                    results,
                    capture_contract_sha256,
                )
            sides[side_name] = (side, source_root, sarif_path, results)

        baseline_side = family.get("baseline")
        candidate_side = family.get("candidate")
        baseline_manifest_sarif = (
            baseline_side.get("sarifPath") if isinstance(baseline_side, dict) else None
        )
        candidate_manifest_sarif = (
            candidate_side.get("sarifPath") if isinstance(candidate_side, dict) else None
        )
        labels_parent = PurePosixPath(labels_path).parent
        baseline_label_sarif = labels.get("baselineSarif")
        candidate_label_sarif = labels.get("candidateSarif")
        if isinstance(baseline_label_sarif, str):
            baseline_label_sarif = (labels_parent / baseline_label_sarif).as_posix()
        if isinstance(candidate_label_sarif, str):
            candidate_label_sarif = (labels_parent / candidate_label_sarif).as_posix()
        if baseline_label_sarif != baseline_manifest_sarif:
            self._add("LABEL009", labels_path, "baseline SARIF path differs from manifest")
        if candidate_label_sarif != candidate_manifest_sarif:
            self._add("LABEL010", labels_path, "candidate SARIF path differs from manifest")
        if "baseline" in sides and "candidate" in sides:
            baseline_root = sides["baseline"][1]
            candidate_root = sides["candidate"][1]
            if (
                baseline_root == candidate_root
                or baseline_root.startswith(candidate_root + "/")
                or candidate_root.startswith(baseline_root + "/")
            ):
                self._add(
                    "MANIFEST008",
                    "manifest.json",
                    "baseline and candidate source roots overlap",
                )
            if sides["baseline"][2] == sides["candidate"][2]:
                self._add(
                    "MANIFEST009",
                    "manifest.json",
                    "baseline and candidate SARIF inputs are identical",
                )
            self._scan_proof_sources(labels, labels_path, sides)
            self._scan_label_partition(labels, labels_path, sides)
            self._scan_order_leakage(labels, labels_path, sides)

    def _scan_proof_sources(
        self,
        labels: Mapping[str, object],
        labels_path: str,
        sides: Mapping[str, tuple[Mapping[str, object], str, str, object]],
    ) -> None:
        """Bind optional transformation hashes to admitted files on the correct side."""

        labels_parent = PurePosixPath(labels_path).parent
        required_sides_by_category = {
            "relationships": frozenset({"baseline", "candidate"}),
            "new": frozenset({"candidate"}),
            "resolved": frozenset({"baseline"}),
            "ambiguities": frozenset({"baseline", "candidate"}),
        }
        for category in ("relationships", "new", "resolved", "ambiguities"):
            entries = labels.get(category)
            if not isinstance(entries, list):
                continue
            for index, entry in enumerate(entries):
                if not isinstance(entry, dict):
                    continue
                proof = entry.get("sourceTransformation")
                if not isinstance(proof, dict):
                    continue
                for side_name in ("baseline", "candidate"):
                    path_key = f"{side_name}SourcePath"
                    hash_key = f"{side_name}FileSha256"
                    raw_path = proof.get(path_key)
                    expected_hash = proof.get(hash_key)
                    owner = f"{category}/{index}/{path_key}"
                    required = side_name in required_sides_by_category[category]
                    if raw_path is None or expected_hash is None:
                        if required or raw_path is not None or expected_hash is not None:
                            self._add(
                                "LABEL016",
                                labels_path,
                                f"{owner} requires a paired source path and SHA-256",
                            )
                        continue
                    if not _is_canonical_relative_path(raw_path):
                        self._add(
                            "LABEL016",
                            labels_path,
                            f"{owner} is not a canonical relative path",
                        )
                        continue
                    source_root = sides[side_name][1]
                    path_value = str(raw_path)
                    candidates = {
                        path_value,
                        (labels_parent / PurePosixPath(path_value)).as_posix(),
                    }
                    resolved = sorted(
                        candidate
                        for candidate in candidates
                        if candidate in self.files
                        and candidate.startswith(source_root + "/")
                    )
                    if len(resolved) != 1:
                        self._add(
                            "LABEL016",
                            labels_path,
                            f"{owner} does not resolve exactly once inside the {side_name} source root",
                        )
                        continue
                    if required:
                        endpoint_value = entry.get(side_name)
                        endpoint_selectors = (
                            endpoint_value
                            if isinstance(endpoint_value, list)
                            else [endpoint_value]
                        )
                        endpoint_uris = {
                            selector.get("artifactUri")
                            for selector in endpoint_selectors
                            if isinstance(selector, dict)
                            and isinstance(selector.get("artifactUri"), str)
                        }
                        nested = resolved[0][len(source_root) + 1 :]
                        if endpoint_uris != {nested}:
                            self._add(
                                "LABEL019",
                                labels_path,
                                f"{owner} does not identify every applicable endpoint source file",
                            )
                    payload = self._read(resolved[0])
                    if (
                        payload is None
                        or not isinstance(expected_hash, str)
                        or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
                        or hashlib.sha256(payload).hexdigest() != expected_hash
                    ):
                        self._add(
                            "LABEL017",
                            labels_path,
                            f"{owner} SHA-256 does not match admitted source bytes",
                        )

    def _scan_label_partition(
        self,
        labels: Mapping[str, object],
        labels_path: str,
        sides: Mapping[str, tuple[Mapping[str, object], str, str, object]],
    ) -> None:
        """Prove selectors uniquely and exhaustively partition both SARIF sides."""

        result_keys: dict[str, list[tuple[object, ...] | None]] = {}
        positions: dict[str, dict[tuple[object, ...], list[int]]] = {}
        for side_name in ("baseline", "candidate"):
            raw_results = sides[side_name][3]
            if not isinstance(raw_results, list):
                return
            keys = [selector_from_sarif(result) for result in raw_results]
            result_keys[side_name] = keys
            side_positions: dict[tuple[object, ...], list[int]] = {}
            for index, key in enumerate(keys):
                if key is None:
                    self._add(
                        "SARIF006",
                        sides[side_name][2],
                        f"result {index} has no complete, ordered selector",
                    )
                    continue
                side_positions.setdefault(key, []).append(index)
            positions[side_name] = side_positions

        assigned: dict[str, set[int]] = {"baseline": set(), "candidate": set()}

        def assign(side_name: str, value: object, owner: str) -> None:
            key = selector_from_label(value)
            if key is None:
                self._add(
                    "LABEL011",
                    labels_path,
                    f"{owner} has an invalid or inverted {side_name} selector",
                )
                return
            matches = positions[side_name].get(key, [])
            if len(matches) != 1:
                self._add(
                    "LABEL012",
                    labels_path,
                    f"{owner} {side_name} selector resolves {len(matches)} times",
                )
                return
            result_index = matches[0]
            if result_index in assigned[side_name]:
                self._add(
                    "LABEL013",
                    labels_path,
                    f"{owner} duplicates an assigned {side_name} endpoint",
                )
                return
            assigned[side_name].add(result_index)

        relationships = labels.get("relationships")
        if isinstance(relationships, list):
            for index, relationship in enumerate(relationships):
                if not isinstance(relationship, dict):
                    continue
                owner = f"relationships/{index}"
                assign("baseline", relationship.get("baseline"), owner)
                assign("candidate", relationship.get("candidate"), owner)

        new_findings = labels.get("new")
        if isinstance(new_findings, list):
            for index, finding in enumerate(new_findings):
                if isinstance(finding, dict):
                    assign("candidate", finding.get("candidate"), f"new/{index}")

        resolved_findings = labels.get("resolved")
        if isinstance(resolved_findings, list):
            for index, finding in enumerate(resolved_findings):
                if isinstance(finding, dict):
                    assign("baseline", finding.get("baseline"), f"resolved/{index}")

        ambiguities = labels.get("ambiguities")
        if isinstance(ambiguities, list):
            for index, ambiguity in enumerate(ambiguities):
                if not isinstance(ambiguity, dict):
                    continue
                baseline = ambiguity.get("baseline")
                candidate = ambiguity.get("candidate")
                shape = ambiguity.get("shape")
                baseline_count = len(baseline) if isinstance(baseline, list) else 0
                candidate_count = len(candidate) if isinstance(candidate, list) else 0
                cardinality_is_valid = (
                    shape == "one-to-many"
                    and baseline_count == 1
                    and candidate_count >= 2
                ) or (
                    shape == "many-to-one"
                    and baseline_count >= 2
                    and candidate_count == 1
                ) or (
                    shape == "many-to-many"
                    and baseline_count >= 2
                    and candidate_count >= 2
                )
                if not cardinality_is_valid:
                    self._add(
                        "LABEL015",
                        labels_path,
                        f"ambiguities/{index} cardinality contradicts its shape",
                    )
                if isinstance(baseline, list):
                    for member_index, selector in enumerate(baseline):
                        assign(
                            "baseline",
                            selector,
                            f"ambiguities/{index}/baseline/{member_index}",
                        )
                if isinstance(candidate, list):
                    for member_index, selector in enumerate(candidate):
                        assign(
                            "candidate",
                            selector,
                            f"ambiguities/{index}/candidate/{member_index}",
                        )

        for side_name in ("baseline", "candidate"):
            expected = set(range(len(result_keys[side_name])))
            unassigned = sorted(expected - assigned[side_name])
            if unassigned:
                self._add(
                    "LABEL014",
                    labels_path,
                    f"{side_name} SARIF has {len(unassigned)} unassigned result endpoint(s)",
                )

    def _verify_side_hashes(
        self,
        side: Mapping[str, object],
        source_root: str,
        source_files: Sequence[str],
        sarif_path: str,
    ) -> None:
        expected_tree = side.get("sourceTreeSha256")
        actual_tree = source_tree_sha256(source_root, source_files, self._read)
        if expected_tree != actual_tree:
            self._add("HASH001", source_root, "source tree SHA-256 does not match")
        payload = self._read(sarif_path)
        if payload is not None:
            actual_sarif = hashlib.sha256(payload).hexdigest()
            if side.get("projectedSarifSha256") != actual_sarif:
                self._add("HASH002", sarif_path, "projected SARIF SHA-256 does not match")
            if side.get("projectedSarifBytes") != len(payload):
                self._add("HASH004", sarif_path, "projected SARIF byte count does not match")
        raw_hash = side.get("rawCaptureSha256")
        if not isinstance(raw_hash, str) or re.fullmatch(r"[0-9a-f]{64}", raw_hash) is None:
            self._add("HASH003", "manifest.json", "raw capture SHA-256 is not fixed")
        raw_bytes = side.get("rawCaptureBytes")
        if type(raw_bytes) is not int or not 1 <= raw_bytes <= MAX_JSON_BYTES:
            self._add("HASH005", "manifest.json", "raw capture byte count is not fixed")

    def _scan_source(self, relative: str, label_tokens: set[str]) -> None:
        payload = self._read(relative)
        if payload is None:
            return
        text = self._decode_text(relative, payload)
        if text is None:
            return
        folded = text.casefold()
        normalized_folded = " ".join(folded.split())
        for token in sorted(label_tokens):
            target = normalized_folded if " " in token else folded
            if token not in target:
                continue
            if " " not in token:
                pattern = re.compile(
                    rf"(?<![A-Za-z0-9_-]){re.escape(token)}(?![A-Za-z0-9_-])",
                    re.IGNORECASE,
                )
                if pattern.search(text) is None:
                    continue
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            self._add("SOURCE002", relative, f"source contains label token sha256:{digest}")
        if MARKER_PATTERN.search(text):
            self._add("SOURCE003", relative, "source contains a known ground-truth marker")
        for identifier in re.findall(r"\b[A-Za-z_$][A-Za-z0-9_$-]*\b", text):
            if SUSPICIOUS_IDENTIFIER_PATTERN.fullmatch(identifier):
                self._add(
                    "SOURCE004",
                    relative,
                    f"suspicious identity-encoding identifier: {identifier}",
                )
            normalized_identifier = re.sub(
                r"[^a-z0-9]",
                "",
                identifier.casefold(),
            )
            digest = self.normalized_label_ids.get(normalized_identifier)
            if digest is not None:
                self._add(
                    "SOURCE002",
                    relative,
                    f"source identifier contains label ID sha256:{digest}",
                )
        for _, _, comment in java_comments(text):
            normalized_comment = re.sub(r"[^a-z0-9]", "", comment.casefold())
            for normalized_id, digest in self.normalized_label_ids.items():
                if normalized_id in normalized_comment:
                    self._add(
                        "SOURCE002",
                        relative,
                        f"source comment contains label ID sha256:{digest}",
                    )
        self._scan_adjacent_comments(relative, text)

    def _scan_adjacent_comments(self, relative: str, text: str) -> None:
        call_lines = {
            index
            for index, line in enumerate(text.splitlines(), start=1)
            if re.search(r"\bprintStackTrace\s*\(", line)
        }
        if not call_lines:
            return
        for start_line, end_line, comment in java_comments(text):
            if not (MARKER_PATTERN.search(comment) or CORRESPONDENCE_COMMENT_PATTERN.search(comment)):
                continue
            if any(
                (end_line <= line and line - end_line <= 2)
                or (start_line >= line and start_line - line <= 2)
                or start_line <= line <= end_line
                for line in call_lines
            ):
                self._add(
                    "SOURCE005",
                    relative,
                    "identity/correspondence comment is adjacent to an analysed call",
                )

    def _sarif_results(self, sarif_path: str, document: object) -> list[object]:
        if not isinstance(document, dict) or not isinstance(document.get("runs"), list):
            self._add("SARIF003", sarif_path, "SARIF runs array is missing")
            return []
        results: list[object] = []
        for run in document["runs"]:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list):
                self._add("SARIF004", sarif_path, "SARIF run results array is missing")
                continue
            results.extend(run["results"])
            if len(results) > MAX_RESULTS:
                self._add("LIMIT007", sarif_path, f"SARIF results exceed {MAX_RESULTS}")
                return results[:MAX_RESULTS]
        return results

    def _scan_sparse_results(self, sarif_path: str, results: Sequence[object]) -> None:
        for index, result in enumerate(results):
            if not isinstance(result, dict):
                self._add("SARIF005", sarif_path, f"result {index} is not an object")
                continue
            stack: list[object] = [result]
            while stack:
                value = stack.pop()
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key in {"fingerprints", "partialFingerprints"}:
                            self._add(
                                "SPARSE001",
                                sarif_path,
                                f"result {index} contains producer fingerprints",
                            )
                        if key == "snippet":
                            self._add(
                                "SPARSE002",
                                sarif_path,
                                f"result {index} contains an embedded snippet",
                            )
                        stack.append(child)
                elif isinstance(value, list):
                    stack.extend(value)

    def _scan_sarif_ground_truth(self, sarif_path: str, document: object) -> None:
        """Reject label IDs and explicit ground-truth markers anywhere in SARIF."""

        stack: list[object] = [document]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                for key, child in value.items():
                    self._scan_sarif_ground_truth_text(sarif_path, key, "key")
                    stack.append(child)
            elif isinstance(value, list):
                stack.extend(value)
            elif isinstance(value, str):
                self._scan_sarif_ground_truth_text(sarif_path, value, "value")

    def _scan_sarif_ground_truth_text(
        self,
        sarif_path: str,
        value: str,
        kind: str,
    ) -> None:
        if MARKER_PATTERN.search(value):
            self._add(
                "SARIF007",
                sarif_path,
                f"SARIF {kind} contains a ground-truth marker",
            )
        for label_id, digest in self.label_ids.items():
            if re.search(
                rf"(?<![A-Za-z0-9_-]){re.escape(label_id)}(?![A-Za-z0-9_-])",
                value,
                re.IGNORECASE,
            ):
                self._add(
                    "SARIF008",
                    sarif_path,
                    f"SARIF {kind} contains label ID sha256:{digest}",
                )
        normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
        for normalized_id, digest in self.normalized_label_ids.items():
            if normalized_id in normalized:
                self._add(
                    "SARIF008",
                    sarif_path,
                    f"SARIF {kind} contains label ID sha256:{digest}",
                )

    def _scan_environmental_json(self, relative: str, document: object) -> None:
        stack: list[tuple[object, str | None]] = [(document, None)]
        while stack:
            value, key = stack.pop()
            if isinstance(value, dict):
                stack.extend((child, child_key) for child_key, child in value.items())
            elif isinstance(value, list):
                stack.extend((child, key) for child in value)
            elif isinstance(value, str):
                normalized_key = re.sub(r"[-_]", "", key or "").casefold()
                is_typed_pointer = (
                    (
                        normalized_key == "jsonpointer"
                        and re.fullmatch(r"(?:/(?:[^~/]|~[01])*)*", value)
                        is not None
                    )
                    or (
                        normalized_key == "pointer"
                        and re.fullmatch(
                            r"/runs/0/results/(?:0|[1-9][0-9]*)/locations/0/"
                            r"physicalLocation/artifactLocation/uri",
                            value,
                        )
                        is not None
                    )
                )
                if (
                    not is_typed_pointer
                    and (
                        POSIX_LOCAL_PATH_PATTERN.search(value)
                        or WINDOWS_LOCAL_PATH_PATTERN.search(value)
                    )
                ):
                    self._add("AMBIENT001", relative, "JSON contains an absolute local path")
                if TIMESTAMP_PATTERN.search(value):
                    self._add("AMBIENT002", relative, "JSON contains a wall-clock timestamp")
                if normalized_key in HOST_KEYS or HOST_VALUE_PATTERN.fullmatch(value):
                    self._add("AMBIENT003", relative, "JSON contains a machine hostname")

    def _scan_experiment_report(
        self,
        relative: str,
        report: Mapping[str, object],
    ) -> None:
        """Bind an implement-v4 decision to one uniquely selected safe variant."""

        manifest_payload = self._read("manifest.json")
        if (
            manifest_payload is None
            or report.get("corpusManifestSha256")
            != hashlib.sha256(manifest_payload).hexdigest()
        ):
            self._add(
                "EXPERIMENT013",
                relative,
                "corpus manifest SHA-256 does not match admitted manifest bytes",
            )
        if report.get("fixedGates") != FIXED_EXPERIMENT_GATES:
            self._add(
                "EXPERIMENT001",
                relative,
                "fixed experiment gates differ from the release safety contract",
            )
        decision = report.get("decision")
        if decision not in {"implement-v4", "document-limitation"}:
            self._add(
                "EXPERIMENT015",
                relative,
                "decision is not an exact supported experiment decision",
            )
        variants = report.get("variants")
        if not isinstance(variants, list):
            self._add("EXPERIMENT002", relative, "variants is not an array")
            return
        by_id: dict[str, list[Mapping[str, object]]] = {}
        for index, value in enumerate(variants):
            if not isinstance(value, dict) or not isinstance(value.get("id"), str):
                self._add(
                    "EXPERIMENT003",
                    relative,
                    f"variant {index} has no stable ID",
                )
                continue
            by_id.setdefault(value["id"], []).append(value)
            self._scan_variant_projection(relative, index, value)
            metrics = value.get("metrics")
            by_family = metrics.get("byFamily") if isinstance(metrics, dict) else None
            if isinstance(by_family, list):
                family_ids = [
                    item.get("familyId")
                    for item in by_family
                    if isinstance(item, dict)
                ]
                if len(family_ids) != len(set(family_ids)):
                    self._add(
                        "EXPERIMENT004",
                        relative,
                        f"variant {index} repeats a family metrics ID",
                    )
        duplicates = sorted(key for key, values in by_id.items() if len(values) != 1)
        if duplicates:
            self._add(
                "EXPERIMENT005",
                relative,
                "variant IDs are not unique",
            )
        variant_ids = [
            value.get("id") if isinstance(value, dict) else None
            for value in variants
        ]
        if variant_ids != list(EXPERIMENT_VARIANT_IDS):
            self._add(
                "EXPERIMENT012",
                relative,
                "variant set/order differs from the five predeclared evidence variants",
            )

        selected_id = report.get("selectedVariant")
        selected: Mapping[str, object] | None = None
        if selected_id is not None:
            matches = by_id.get(selected_id, []) if isinstance(selected_id, str) else []
            if len(matches) != 1:
                self._add(
                    "EXPERIMENT006",
                    relative,
                    "selectedVariant does not resolve exactly once",
                )
            else:
                selected = matches[0]
        if decision == "implement-v4":
            implementation_bound = self._evidence_reference_bound(
                relative,
                "implementation",
                report.get("implementation"),
                "path",
                "sha256",
            )
            if selected is None:
                self._add(
                    "EXPERIMENT007",
                    relative,
                    "implement-v4 has no uniquely selected variant",
                )
            else:
                if not IMPLEMENT_V4_ROLE_VALIDATORS_AVAILABLE:
                    self._add(
                        "EXPERIMENT016",
                        relative,
                        "implement-v4 is disabled until role-specific evidence validators exist",
                    )
                if not self._variant_passes_gates(
                    selected,
                    relative,
                    implementation_bound=implementation_bound,
                ):
                    self._add(
                        "EXPERIMENT008",
                        relative,
                        "implement-v4 selected a variant that fails one or more fixed gates",
                    )

    def _scan_variant_projection(
        self,
        relative: str,
        index: int,
        variant: Mapping[str, object],
    ) -> None:
        projection = variant.get("gateProjection")
        if not isinstance(projection, dict):
            self._add(
                "EXPERIMENT009",
                relative,
                f"variant {index} has no explicit gate projection",
            )
            return
        bindings = self._computed_gate_bindings(variant)
        if bindings is None:
            self._add(
                "EXPERIMENT011",
                relative,
                f"variant {index} has incomplete or inconsistent gate evidence",
            )
            return
        for projection_key, evidence_value in bindings.items():
            if projection.get(projection_key) != evidence_value:
                self._add(
                    "EXPERIMENT010",
                    relative,
                    f"variant {index} gate projection disagrees with bound evidence for {projection_key}",
                )

    def _variant_passes_gates(
        self,
        variant: Mapping[str, object],
        report_path: str,
        *,
        implementation_bound: bool,
    ) -> bool:
        projection = variant.get("gateProjection")
        if not isinstance(projection, dict):
            return False
        bindings = self._computed_gate_bindings(variant)
        if bindings is None or any(
            projection.get(key) != value for key, value in bindings.items()
        ):
            return False
        artifacts_bound = self._variant_artifacts_bound(
            report_path,
            variant,
        )
        if not implementation_bound or not artifacts_bound:
            return False
        if not IMPLEMENT_V4_ROLE_VALIDATORS_AVAILABLE:
            # A digest proves bytes, not that those bytes are the claimed
            # implementation, holdout, determinism, or resource artifact.
            # Stay fail-closed until each evidence role has a parser and
            # cross-reference validator tied to its producer contract.
            return False

        def rate_at_least(key: str, minimum: float) -> bool:
            value = projection.get(key)
            return (
                isinstance(value, (int, float))
                and not isinstance(value, bool)
                and value >= minimum
            )

        return (
            rate_at_least("pmdPrecision", 0.95)
            and rate_at_least("pmdRecall", 0.8)
            and rate_at_least("aggregatePrecision", 0.95)
            and rate_at_least("aggregateRecall", 0.9)
            and projection.get("silentlyMatchedAmbiguity") == 0
            and projection.get("sourceSideLeakage") == 0
            and projection.get("containmentRegressions") == 0
            and projection.get("rootConfusions") == 0
            and projection.get("unexplainedIngestionFailures") == 0
            and projection.get("structuralFailures") == 0
            and projection.get("developmentCorpusGreen") is True
            and projection.get("semgrepNoRegression") is True
            and projection.get("gitleaksNoRegression") is True
            and projection.get("repeatedRunByteIdentical") is True
            and projection.get("crossPlatformByteIdentical") is True
            and projection.get("resourceBudgetsWithinLimits") is True
            and projection.get("scenarioMatrixPassed") is True
            and projection.get("corpusSpecificPreflightRequired") is False
        )

    def _evidence_reference_bound(
        self,
        report_path: str,
        owner: str,
        value: object,
        path_key: str,
        hash_key: str,
    ) -> bool:
        if not isinstance(value, dict):
            return False
        path = value.get(path_key)
        digest = value.get(hash_key)
        if path is None and digest is None:
            return False
        if (
            not _is_canonical_relative_path(path)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            self._add(
                "EXPERIMENT014",
                report_path,
                f"{owner} evidence path and SHA-256 are not a complete portable pair",
            )
            return False
        assert isinstance(path, str)
        payload = self._read(path)
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            self._add(
                "EXPERIMENT014",
                report_path,
                f"{owner} SHA-256 does not match admitted evidence bytes",
            )
            return False
        return True

    def _variant_artifacts_bound(
        self,
        report_path: str,
        variant: Mapping[str, object],
    ) -> bool:
        references: list[tuple[str, object, str, str]] = []
        references.append(
            (
                "variant experiment",
                variant.get("experimentEvidence"),
                "path",
                "sha256",
            )
        )
        release = variant.get("releaseEvidence")
        if isinstance(release, dict):
            references.extend(
                (
                    f"release {name}",
                    release.get(name),
                    "reportPath",
                    "reportSha256",
                )
                for name in ("holdout", "developmentCorpus")
            )
        production = variant.get("productionApplicability")
        references.append(
            (
                "no-trusted-hash matrix",
                production,
                "evidencePath",
                "evidenceSha256",
            )
        )
        determinism = variant.get("determinism")
        if isinstance(determinism, dict):
            for name in ("linux", "windows", "comparison"):
                references.append(
                    (
                        f"determinism {name}",
                        determinism.get(name),
                        "artifactPath",
                        "artifactSha256",
                    )
                )
        resources = variant.get("resources")
        references.append(
            (
                "resource coordinator",
                resources,
                "evidencePath",
                "evidenceSha256",
            )
        )
        if isinstance(resources, dict) and isinstance(resources.get("cells"), list):
            references.extend(
                (
                    f"resource cell {index}",
                    cell,
                    "artifactPath",
                    "artifactSha256",
                )
                for index, cell in enumerate(resources["cells"])
            )
        results = [
            self._evidence_reference_bound(
                report_path,
                owner,
                value,
                path_key,
                hash_key,
            )
            for owner, value, path_key, hash_key in references
        ]
        return all(results)

    @staticmethod
    def _computed_gate_bindings(
        variant: Mapping[str, object],
    ) -> dict[str, object] | None:
        metrics = variant.get("metrics")
        pmd = metrics.get("aggregate") if isinstance(metrics, dict) else None
        families = metrics.get("byFamily") if isinstance(metrics, dict) else None
        ambiguity = variant.get("ambiguity")
        ingestion = variant.get("ingestion")
        security = variant.get("security")
        determinism = variant.get("determinism")
        resources = variant.get("resources")
        scenarios = variant.get("scenarios")
        production = variant.get("productionApplicability")
        release = variant.get("releaseEvidence")
        holdout = release.get("holdout") if isinstance(release, dict) else None
        development = (
            release.get("developmentCorpus") if isinstance(release, dict) else None
        )
        holdout_metrics = holdout.get("metrics") if isinstance(holdout, dict) else None
        producers = holdout.get("byProducer") if isinstance(holdout, dict) else None
        required_objects = (
            pmd,
            ambiguity,
            ingestion,
            security,
            determinism,
            resources,
            holdout,
            development,
            holdout_metrics,
            production,
        )
        if any(not isinstance(value, dict) for value in required_objects):
            return None
        no_hash_metrics = production.get("metricsWithoutTrustedTreeHashes")
        if not isinstance(no_hash_metrics, dict) or not Scanner._metrics_are_consistent(
            no_hash_metrics,
            expected_relationships=19,
        ):
            return None
        no_hash_scenarios = production.get("scenariosWithoutTrustedTreeHashes")
        no_hash_evidence = Scanner._scenario_evidence(no_hash_scenarios)
        if (
            production.get("trustedTreeHashPreflightEnabled") is not False
            or no_hash_evidence is None
            or type(production.get("corpusSpecificPreflightRequired")) is not bool
        ):
            return None
        corpus_specific_preflight_required = not (
            no_hash_evidence["passed"] is True
            and no_hash_evidence["sourceSideLeakage"] == 0
            and no_hash_evidence["containmentViolations"] == 0
            and no_hash_evidence["rootConfusions"] == 0
            and no_hash_evidence["unexplainedIngestionFailures"] == 0
            and no_hash_evidence["structuralFailures"] == 0
            and float(no_hash_metrics["precision"]) >= 0.95
            and float(no_hash_metrics["recall"]) >= 0.8
        )
        if production["corpusSpecificPreflightRequired"] is not corpus_specific_preflight_required:
            return None
        if (
            not isinstance(families, list)
            or not isinstance(producers, list)
            or not isinstance(scenarios, list)
        ):
            return None
        scenario_evidence = Scanner._scenario_evidence(scenarios)
        if scenario_evidence is None:
            return None
        ambiguity_counts = (
            ambiguity.get("labelledUnits"),
            ambiguity.get("correctRefusals"),
            ambiguity.get("incorrectAutoMatches"),
        )
        if (
            any(type(value) is not int or value < 0 for value in ambiguity_counts)
            or ambiguity["labelledUnits"] != 3
            or ambiguity["correctRefusals"] + ambiguity["incorrectAutoMatches"]
            != ambiguity["labelledUnits"]
        ):
            return None
        ingestion_counts = (
            ingestion.get("casesEvaluated"),
            ingestion.get("failures"),
            ingestion.get("structuralFailures"),
        )
        if (
            any(type(value) is not int or value < 0 for value in ingestion_counts)
            or ingestion["casesEvaluated"] != 4
            or ingestion["failures"] > ingestion["casesEvaluated"]
            or ingestion["structuralFailures"] > ingestion["casesEvaluated"]
        ):
            return None
        resource_limits_passed = Scanner._resource_matrix_passes(resources)
        determinism_evidence = Scanner._determinism_evidence(determinism)
        if resource_limits_passed is None or determinism_evidence is None:
            return None
        if not Scanner._metrics_are_consistent(pmd, expected_relationships=19):
            return None
        family_metrics = [
            value for value in families if isinstance(value, dict)
        ]
        if len(family_metrics) != len(families):
            return None
        family_ids = [value.get("familyId") for value in family_metrics]
        if family_ids != ["pmd-clean-a", "pmd-clean-b"]:
            return None
        family_relationships = {"pmd-clean-a": 8, "pmd-clean-b": 11}
        if any(
            not Scanner._metrics_are_consistent(
                value,
                expected_relationships=family_relationships[str(value["familyId"])],
            )
            for value in family_metrics
        ):
            return None
        for count_key in ("truePositives", "falsePositives", "falseNegatives"):
            if pmd.get(count_key) != sum(
                int(value[count_key]) for value in family_metrics
            ):
                return None

        if holdout.get("relationshipCount") != 75:
            return None
        if not Scanner._metrics_are_consistent(
            holdout_metrics,
            expected_relationships=75,
        ):
            return None
        producer_map: dict[str, Mapping[str, object]] = {}
        for value in producers:
            if not isinstance(value, dict) or not isinstance(
                value.get("producerFamily"), str
            ):
                return None
            producer = value["producerFamily"]
            if producer in producer_map:
                return None
            producer_map[producer] = value
        if set(producer_map) != {"semgrep", "gitleaks", "pmd"}:
            return None
        for value in producer_map.values():
            producer_metrics = value.get("metrics")
            if (
                type(value.get("regressions")) is not int
                or value["regressions"] < 0
                or not isinstance(producer_metrics, dict)
                or not Scanner._metrics_are_consistent(
                    producer_metrics,
                    expected_relationships=25,
                )
            ):
                return None
        for count_key in ("truePositives", "falsePositives", "falseNegatives"):
            if holdout_metrics.get(count_key) != sum(
                int(value["metrics"][count_key])  # type: ignore[index]
                for value in producer_map.values()
            ):
                return None

        def producer_no_regression(name: str) -> bool:
            value = producer_map[name]
            producer_metrics = value["metrics"]
            return (
                value.get("regressions") == 0
                and isinstance(producer_metrics, dict)
                and producer_metrics.get("truePositives") == 25
                and producer_metrics.get("falsePositives") == 0
                and producer_metrics.get("falseNegatives") == 0
                and producer_metrics.get("precision") == 1
                and producer_metrics.get("recall") == 1
                and producer_metrics.get("f1") == 1
            )

        integer_evidence = (
            ambiguity.get("incorrectAutoMatches"),
            ingestion.get("failures"),
            ingestion.get("structuralFailures"),
            security.get("sourceSideLeakage"),
            security.get("containmentRegressions"),
            security.get("rootConfusions"),
            holdout.get("ingestionFailures"),
            holdout.get("structuralFailures"),
            development.get("regressions"),
            development.get("silentlyMatchedAmbiguity"),
        )
        if any(type(value) is not int or value < 0 for value in integer_evidence):
            return None
        boolean_evidence = (
            development.get("passed"),
            determinism_evidence.get("repeatedRunByteIdentical"),
            determinism_evidence.get("linuxWindowsByteIdentical"),
            resources.get("withinDocumentedLimits"),
        )
        if any(type(value) is not bool for value in boolean_evidence):
            return None
        if (
            security.get("sourceSideLeakage") != scenario_evidence["sourceSideLeakage"]
            or security.get("containmentRegressions")
            != scenario_evidence["containmentViolations"]
            or security.get("rootConfusions") != scenario_evidence["rootConfusions"]
        ):
            return None
        return {
            "pmdPrecision": pmd.get("precision"),
            "pmdRecall": pmd.get("recall"),
            "aggregatePrecision": holdout_metrics.get("precision"),
            "aggregateRecall": holdout_metrics.get("recall"),
            "silentlyMatchedAmbiguity": ambiguity.get("incorrectAutoMatches"),
            "sourceSideLeakage": security.get("sourceSideLeakage"),
            "containmentRegressions": security.get("containmentRegressions"),
            "rootConfusions": security.get("rootConfusions"),
            "unexplainedIngestionFailures": (
                ingestion["failures"]
                + holdout["ingestionFailures"]
                + scenario_evidence["unexplainedIngestionFailures"]
            ),
            "structuralFailures": (
                ingestion["structuralFailures"]
                + holdout["structuralFailures"]
                + scenario_evidence["structuralFailures"]
            ),
            "developmentCorpusGreen": (
                development.get("passed") is True
                and development["regressions"] == 0
                and development["silentlyMatchedAmbiguity"] == 0
            ),
            "semgrepNoRegression": producer_no_regression("semgrep"),
            "gitleaksNoRegression": producer_no_regression("gitleaks"),
            "repeatedRunByteIdentical": determinism_evidence[
                "repeatedRunByteIdentical"
            ],
            "crossPlatformByteIdentical": determinism_evidence[
                "linuxWindowsByteIdentical"
            ],
            "resourceBudgetsWithinLimits": resource_limits_passed,
            "scenarioMatrixPassed": scenario_evidence["passed"],
            "corpusSpecificPreflightRequired": corpus_specific_preflight_required,
        }

    @staticmethod
    def _scenario_evidence(value: object) -> dict[str, object] | None:
        if not isinstance(value, list) or len(value) != len(EXPERIMENT_SCENARIO_IDS):
            return None
        if any(not isinstance(item, dict) for item in value):
            return None
        records = [item for item in value if isinstance(item, dict)]
        if [item.get("scenarioId") for item in records] != list(EXPERIMENT_SCENARIO_IDS):
            return None
        count_keys = (
            "acceptedRelationships",
            "baselineReadsFromCandidateRoot",
            "candidateReadsFromBaselineRoot",
            "containmentViolations",
            "unexplainedIngestionFailures",
            "structuralFailures",
        )
        if any(
            type(item.get(key)) is not int or item[key] < 0
            for item in records
            for key in count_keys
        ) or any(
            type(item.get(key)) is not bool
            for item in records
            for key in ("assertionsPassed", "preflightAccepted")
        ):
            return None
        totals = {
            key: sum(int(item[key]) for item in records)
            for key in count_keys
        }
        passed = all(
            item["assertionsPassed"] is True
            and item["baselineReadsFromCandidateRoot"] == 0
            and item["candidateReadsFromBaselineRoot"] == 0
            and item["containmentViolations"] == 0
            and (
                (
                    item["scenarioId"] in FAIL_CLOSED_SCENARIOS
                    and item["preflightAccepted"] is False
                    and item["acceptedRelationships"] == 0
                )
                or (
                    item["scenarioId"] not in FAIL_CLOSED_SCENARIOS
                    and item["preflightAccepted"] is True
                )
            )
            for item in records
        )
        swapped = set(EXPERIMENT_SCENARIO_IDS[6:9])
        root_confusions = sum(
            1
            for item in records
            if item["scenarioId"] in swapped
            and (
                item["preflightAccepted"] is True
                or item["acceptedRelationships"] > 0
                or item["baselineReadsFromCandidateRoot"] > 0
                or item["candidateReadsFromBaselineRoot"] > 0
            )
        )
        return {
            "passed": passed,
            "sourceSideLeakage": (
                totals["baselineReadsFromCandidateRoot"]
                + totals["candidateReadsFromBaselineRoot"]
            ),
            "containmentViolations": totals["containmentViolations"],
            "rootConfusions": root_confusions,
            "unexplainedIngestionFailures": totals[
                "unexplainedIngestionFailures"
            ],
            "structuralFailures": totals["structuralFailures"],
        }

    @staticmethod
    def _determinism_evidence(value: Mapping[str, object]) -> dict[str, bool] | None:
        linux = value.get("linux")
        windows = value.get("windows")
        comparison = value.get("comparison")
        if any(not isinstance(item, dict) for item in (linux, windows, comparison)):
            return None
        assert isinstance(linux, dict)
        assert isinstance(windows, dict)
        assert isinstance(comparison, dict)
        digests = (
            linux.get("firstOutputSha256"),
            linux.get("secondOutputSha256"),
            windows.get("firstOutputSha256"),
            windows.get("secondOutputSha256"),
        )
        if any(
            not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None
            for item in digests
        ) or type(comparison.get("byteIdentical")) is not bool:
            return None
        repeated = digests[0] == digests[1] and digests[2] == digests[3]
        cross_platform = comparison["byteIdentical"] is True and digests[0] == digests[2]
        if (
            value.get("repeatedRunByteIdentical") is not repeated
            or value.get("linuxWindowsByteIdentical") is not cross_platform
        ):
            return None
        return {
            "repeatedRunByteIdentical": repeated,
            "linuxWindowsByteIdentical": cross_platform,
        }

    @staticmethod
    def _resource_matrix_passes(value: Mapping[str, object]) -> bool | None:
        cells = value.get("cells")
        if not isinstance(cells, list) or len(cells) != len(RESOURCE_CELL_KEYS):
            return None
        if any(not isinstance(cell, dict) for cell in cells):
            return None
        records = [cell for cell in cells if isinstance(cell, dict)]
        identities = [
            (
                cell.get("operatingSystem"),
                cell.get("findingCount"),
                cell.get("dataset"),
            )
            for cell in records
        ]
        if identities != list(RESOURCE_CELL_KEYS):
            return None
        cell_results: list[bool] = []
        for cell in records:
            size = cell["findingCount"]
            assert isinstance(size, int)
            numeric_keys = (
                "candidateEdges",
                "maximumComponentSize",
                "elapsedMilliseconds",
                "peakWorkingSetBytes",
                "configuredCandidatePairLimit",
                "configuredAssignmentComponentLimit",
            )
            if any(
                type(cell.get(key)) is not int or cell[key] < 0
                for key in numeric_keys
            ) or any(
                type(cell.get(key)) is not bool
                for key in (
                    "boundedRefusalObserved",
                    "runtimeBudgetEnforced",
                    "withinDocumentedLimits",
                )
            ):
                return None
            elapsed_budget, memory_budget = RESOURCE_RUNTIME_BUDGETS[size]
            runtime_enforced = cell["operatingSystem"] == "ubuntu"
            expected_refusal = cell["dataset"] == "pathological"
            passed = (
                cell["configuredCandidatePairLimit"]
                == MAX_EXPERIMENT_CANDIDATE_EDGES
                and cell["configuredAssignmentComponentLimit"]
                == MAX_EXPERIMENT_COMPONENT_SIZE
                and cell["candidateEdges"] <= MAX_EXPERIMENT_CANDIDATE_EDGES
                and cell["maximumComponentSize"] <= MAX_EXPERIMENT_COMPONENT_SIZE
                and cell["boundedRefusalObserved"] is expected_refusal
                and cell["runtimeBudgetEnforced"] is runtime_enforced
                and (
                    not runtime_enforced
                    or (
                        cell["elapsedMilliseconds"] <= elapsed_budget
                        and cell["peakWorkingSetBytes"] <= memory_budget
                    )
                )
            )
            if cell["withinDocumentedLimits"] is not passed:
                return None
            cell_results.append(passed)
        overall = all(cell_results)
        if value.get("withinDocumentedLimits") is not overall:
            return None
        return overall

    @staticmethod
    def _metrics_are_consistent(
        metrics: Mapping[str, object],
        *,
        expected_relationships: int | None = None,
    ) -> bool:
        counts = [
            metrics.get("truePositives"),
            metrics.get("falsePositives"),
            metrics.get("falseNegatives"),
        ]
        rates = [metrics.get("precision"), metrics.get("recall"), metrics.get("f1")]
        if any(type(value) is not int or value < 0 for value in counts):
            return False
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not 0 <= value <= 1
            for value in rates
        ):
            return False
        true_positives, false_positives, false_negatives = counts
        if (
            expected_relationships is not None
            and true_positives + false_negatives != expected_relationships
        ):
            return False
        precision_denominator = true_positives + false_positives
        recall_denominator = true_positives + false_negatives
        expected_precision = (
            true_positives / precision_denominator
            if precision_denominator
            else float(metrics["precision"])
        )
        expected_recall = (
            true_positives / recall_denominator if recall_denominator else 0.0
        )
        expected_f1 = (
            2 * expected_precision * expected_recall / (expected_precision + expected_recall)
            if expected_precision + expected_recall
            else 0.0
        )
        return all(
            abs(float(observed) - expected) <= 0.000001
            for observed, expected in zip(
                rates,
                (expected_precision, expected_recall, expected_f1),
            )
        )

    def _scan_order_leakage(
        self,
        labels: Mapping[str, object],
        labels_path: str,
        sides: Mapping[str, tuple[Mapping[str, object], str, str, object]],
    ) -> None:
        baseline_results = sides["baseline"][3]
        candidate_results = sides["candidate"][3]
        if not isinstance(baseline_results, list) or not isinstance(candidate_results, list):
            return
        baseline_result_keys = [selector_from_sarif(value) for value in baseline_results]
        candidate_result_keys = [selector_from_sarif(value) for value in candidate_results]
        relationships = labels.get("relationships")
        if not isinstance(relationships, list) or len(relationships) < 2:
            return
        baseline_keys: list[tuple[object, ...]] = []
        candidate_keys: list[tuple[object, ...]] = []
        for relationship in relationships:
            if not isinstance(relationship, dict):
                return
            baseline = selector_from_label(relationship.get("baseline"))
            candidate = selector_from_label(relationship.get("candidate"))
            if baseline is None or candidate is None:
                return
            baseline_keys.append(baseline)
            candidate_keys.append(candidate)
        self._scan_source_order_leakage(
            labels_path,
            sides,
            baseline_keys,
            candidate_keys,
        )
        baseline_positions = unique_positions(baseline_keys, baseline_result_keys)
        candidate_positions = unique_positions(candidate_keys, candidate_result_keys)
        if baseline_positions is None or candidate_positions is None:
            return
        baseline_order = sorted(
            range(len(baseline_positions)),
            key=lambda index: baseline_positions[index],
        )
        candidate_sequence = [candidate_positions[index] for index in baseline_order]
        if not strictly_monotonic(candidate_sequence):
            return
        self._add(
            "ORDER001",
            labels_path,
            "baseline-to-candidate relationships preserve SARIF result order",
        )
        ordered_baseline_keys = [baseline_keys[index] for index in baseline_order]
        ordered_candidate_keys = [candidate_keys[index] for index in baseline_order]
        if ordered_baseline_keys == ordered_candidate_keys:
            return
        baseline_names = [
            PurePosixPath(str(value[1])).name for value in ordered_baseline_keys
        ]
        candidate_names = [
            PurePosixPath(str(value[1])).name for value in ordered_candidate_keys
        ]
        if (
            baseline_names == candidate_names
        ):
            self._add(
                "ORDER002",
                labels_path,
                "relationship order mirrors a basename sequence on both sides",
            )

    def _scan_source_order_leakage(
        self,
        labels_path: str,
        sides: Mapping[str, tuple[Mapping[str, object], str, str, object]],
        baseline_keys: Sequence[tuple[object, ...]],
        candidate_keys: Sequence[tuple[object, ...]],
    ) -> None:
        roots = {
            side_name: sides[side_name][1]
            for side_name in ("baseline", "candidate")
        }
        ordered_files = {
            side_name: sorted(
                relative
                for relative in self.files
                if relative.startswith(root + "/")
            )
            for side_name, root in roots.items()
        }
        positions: dict[str, list[tuple[object, ...]]] = {}
        for side_name, selectors in (
            ("baseline", baseline_keys),
            ("candidate", candidate_keys),
        ):
            try:
                positions[side_name] = [
                    (
                        ordered_files[side_name].index(
                            f"{roots[side_name]}/{selector[1]}"
                        ),
                        *selector[2:],
                    )
                    for selector in selectors
                ]
            except ValueError:
                return
        baseline_positions = positions["baseline"]
        candidate_positions = positions["candidate"]
        baseline_order = sorted(
            range(len(baseline_positions)),
            key=lambda index: baseline_positions[index],
        )
        if not strictly_monotonic(
            [candidate_positions[index] for index in baseline_order]
        ):
            return
        self._add(
            "ORDER003",
            labels_path,
            "baseline-to-candidate relationships preserve full source-selector order",
        )

def source_tree_sha256(
    source_root: str,
    source_files: Sequence[str],
    reader: object,
) -> str:
    """Hashes sorted source file hashes and root-relative portable paths."""

    lines: list[str] = []
    read = reader
    for relative in sorted(source_files):
        payload = read(relative)  # type: ignore[operator]
        if payload is None:
            continue
        nested = relative[len(source_root) + 1 :]
        lines.append(f"{hashlib.sha256(payload).hexdigest()}  {nested}\n")
    return hashlib.sha256("".join(lines).encode("ascii")).hexdigest()


def selector_from_label(value: object) -> tuple[object, ...] | None:
    if not isinstance(value, dict) or not isinstance(value.get("region"), dict):
        return None
    region = value["region"]
    keys = ("startLine", "startColumn", "endLine", "endColumn")
    if not _region_is_ordered(region, keys):
        return None
    if not all(isinstance(value.get(key), str) for key in ("ruleId", "artifactUri", "message")):
        return None
    if not _is_canonical_relative_path(value.get("artifactUri")):
        return None
    return (
        value["ruleId"],
        value["artifactUri"],
        region["startLine"],
        region["startColumn"],
        region["endLine"],
        region["endColumn"],
        value["message"],
    )


def selector_from_sarif(value: object) -> tuple[object, ...] | None:
    if not isinstance(value, dict):
        return None
    rule_id = value.get("ruleId")
    message = value.get("message")
    locations = value.get("locations")
    if not isinstance(rule_id, str) or not isinstance(message, dict):
        return None
    message_text = message.get("text")
    if not isinstance(message_text, str) or not isinstance(locations, list) or not locations:
        return None
    location = locations[0]
    if not isinstance(location, dict):
        return None
    physical = location.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict) or not isinstance(region, dict):
        return None
    uri = artifact.get("uri")
    keys = ("startLine", "startColumn", "endLine", "endColumn")
    if (
        not isinstance(uri, str)
        or not _is_canonical_relative_path(uri)
        or not _region_is_ordered(region, keys)
    ):
        return None
    return (
        rule_id,
        uri,
        region["startLine"],
        region["startColumn"],
        region["endLine"],
        region["endColumn"],
        message_text,
    )


def _region_is_ordered(
    region: Mapping[str, object],
    keys: Sequence[str],
) -> bool:
    if any(type(region.get(key)) is not int or region[key] < 1 for key in keys):
        return False
    start = (region["startLine"], region["startColumn"])
    end = (region["endLine"], region["endColumn"])
    return end >= start


def _is_canonical_relative_path(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
    ):
        return False
    if re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*",
        value,
    ) is None:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
    )


def unique_positions(
    selectors: Sequence[tuple[object, ...]],
    results: Sequence[tuple[object, ...] | None],
) -> list[int] | None:
    positions: list[int] = []
    for selector in selectors:
        matches = [index for index, value in enumerate(results) if value == selector]
        if len(matches) != 1:
            return None
        positions.append(matches[0])
    return positions


def strictly_monotonic(values: Sequence[object]) -> bool:
    return all(left < right for left, right in zip(values, values[1:])) or all(
        left > right for left, right in zip(values, values[1:])
    )


def java_comments(text: str) -> Iterator[tuple[int, int, str]]:
    """Yields Java comments while ignoring comment markers inside strings."""

    index = 0
    line = 1
    length = len(text)
    while index < length:
        character = text[index]
        if character == "\n":
            line += 1
            index += 1
            continue
        if character in {'"', "'"}:
            quote = character
            index += 1
            while index < length:
                if text[index] == "\\":
                    index += 2
                elif text[index] == quote:
                    index += 1
                    break
                else:
                    if text[index] == "\n":
                        line += 1
                    index += 1
            continue
        if text.startswith("//", index):
            start_line = line
            end = text.find("\n", index + 2)
            if end < 0:
                end = length
            yield start_line, start_line, text[index + 2 : end]
            index = end
            continue
        if text.startswith("/*", index):
            start_line = line
            end = text.find("*/", index + 2)
            if end < 0:
                end = length - 2
            content = text[index + 2 : end]
            end_line = line + content.count("\n")
            yield start_line, end_line, content
            line = end_line
            index = min(length, end + 2)
            continue
        index += 1


def scan_research_root(
    root: Path,
    *,
    source_only: bool = False,
) -> tuple[Finding, ...]:
    """Returns all deterministic findings for one caller-supplied root."""

    return Scanner(root).scan(source_only=source_only)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reject sparse-SARIF research corpus ground-truth contamination."
    )
    parser.add_argument("--research-root", required=True, type=Path)
    parser.add_argument(
        "--source-only",
        action="store_true",
        help="validate pre-capture labels and source trees without requiring SARIF or manifest",
    )
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    findings = scan_research_root(
        parsed.research_root,
        source_only=parsed.source_only,
    )
    if findings:
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        print(
            f"Sparse-SARIF contamination scan rejected {len(findings)} finding(s).",
            file=sys.stderr,
        )
        return 1
    print(f"Sparse-SARIF contamination scan passed ({POLICY_VERSION}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
