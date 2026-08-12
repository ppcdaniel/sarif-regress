#!/usr/bin/env python3
"""Compose authenticated sparse-experiment evidence without network access.

The caller is responsible for downloading artifacts with GitHub's digest-verifying
download action and for recording the unmodified workflow/artifact API responses.
This tool treats those files and every artifact byte as untrusted input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Mapping, Sequence


MAX_JSON_BYTES: Final = 64 * 1024 * 1024
MAX_JSON_DEPTH: Final = 64
MAX_JSON_NODES: Final = 1_000_000
MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
REPOSITORY_NAME: Final = "ppcdaniel/sarif-regress"
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
COMMIT_PATTERN: Final = re.compile(r"[0-9a-f]{40}")
MANIFEST_LINE_PATTERN: Final = re.compile(
    r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)"
)
VARIANT_IDS: Final = (
    "sarif-only-control",
    "exact-region-snippet",
    "token-window",
    "relative-context",
    "agreement-only-combination",
)
VARIANT_DESCRIPTIONS: Final = {
    "sarif-only-control": "SARIF-only control without repository context.",
    "exact-region-snippet": "Exact-region source snippet continuity.",
    "token-window": "Bounded token-window source continuity.",
    "relative-context": "Bounded relative source-context continuity.",
    "agreement-only-combination": (
        "Agreement-only combination of predeclared source-context evidence."
    ),
}
PRODUCER_ORDER: Final = ("semgrep", "gitleaks", "pmd")
RELATIONSHIPS_PER_PRODUCER: Final = 25
RESOURCE_CELL_KEYS: Final = tuple(
    (operating_system, finding_count, dataset)
    for operating_system in ("ubuntu", "windows")
    for finding_count in (1_000, 10_000, 100_000)
    for dataset in ("unique", "pathological")
)
ROLE_CONFIG: Final = {
    "release": {
        "workflow": ".github/workflows/holdout-validation.yml",
        "artifacts": (
            "holdout-linux",
            "holdout-windows",
            "holdout-cross-platform",
        ),
        "kind": "sparse-experiment-release-evidence/v1",
        "projectionKind": "sparse-experiment-release-projection/v1",
    },
    "determinism": {
        "workflow": ".github/workflows/determinism.yml",
        "artifacts": (
            "determinism-linux",
            "determinism-windows",
            "cross-platform-determinism",
        ),
        "kind": "sparse-experiment-determinism-evidence/v1",
        "projectionKind": "sparse-experiment-determinism-projection/v1",
    },
    "resources": {
        "workflow": ".github/workflows/benchmarks.yml",
        "artifacts": tuple(
            f"benchmark-{finding_count}-{dataset}-{platform}"
            for finding_count in (1_000, 10_000, 100_000)
            for dataset in ("unique", "pathological")
            for platform in ("linux", "windows")
        )
        + ("benchmark-cross-platform",),
        "kind": "sparse-experiment-resource-evidence/v1",
        "projectionKind": "sparse-experiment-resource-projection/v1",
    },
}


class CompositionError(RuntimeError):
    """Raised when downloaded evidence cannot be admitted safely."""


@dataclass(frozen=True)
class ArtifactIdentity:
    """Authenticated GitHub artifact identity and extracted directory."""

    name: str
    artifact_id: int
    digest: str
    root: Path


@dataclass(frozen=True)
class WorkflowIdentity:
    """Authenticated exact-head workflow evidence for one supporting role."""

    run_id: int
    source_head_sha: str
    artifacts: tuple[ArtifactIdentity, ...]


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CompositionError(f"Duplicate JSON property {key!r}.")
        result[key] = value
    return result


def _parse_bounded_integer(value: str) -> int:
    if len(value.lstrip("-")) > 16:
        raise CompositionError("JSON integer exceeds the interoperable safe range.")
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise CompositionError("JSON integer exceeds the interoperable safe range.")
    return parsed


def _reject_nonfinite_number(value: str) -> object:
    raise CompositionError(f"Non-finite JSON number {value!r} is prohibited.")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise CompositionError("JSON floating-point value is not finite.")
    return parsed


def _validate_json_shape(value: object) -> None:
    """Validate depth/node bounds in O(n) time and O(d) traversal space."""

    nodes = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise CompositionError("JSON document exceeds the node limit.")
        if depth > MAX_JSON_DEPTH:
            raise CompositionError("JSON document exceeds the nesting-depth limit.")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)


def read_bounded_bytes(path: Path, maximum_bytes: int = MAX_JSON_BYTES) -> bytes:
    """Read one stable regular file while rejecting links and oversized input."""

    try:
        before = path.lstat()
    except OSError as error:
        raise CompositionError(f"Cannot inspect evidence file {path}: {error}") from error
    if path.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise CompositionError(f"Evidence path is not a regular file: {path}.")
    if before.st_size <= 0 or before.st_size > maximum_bytes:
        raise CompositionError(f"Evidence file has an invalid size: {path}.")
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum_bytes + 1)
        after = path.lstat()
    except OSError as error:
        raise CompositionError(f"Cannot read evidence file {path}: {error}") from error
    if (
        len(payload) != before.st_size
        or opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
        or after.st_size != before.st_size
        or after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_mtime_ns != before.st_mtime_ns
        or path.is_symlink()
        or not stat.S_ISREG(after.st_mode)
    ):
        raise CompositionError(f"Evidence file changed while being read: {path}.")
    return payload


def require_real_directory(path: Path, owner: str) -> None:
    """Reject missing, linked, junction-backed, or non-directory containers."""

    try:
        status = path.lstat()
    except OSError as error:
        raise CompositionError(f"Cannot inspect {owner} directory {path}: {error}") from error
    junction_probe = getattr(path, "is_junction", None)
    if (
        path.is_symlink()
        or bool(callable(junction_probe) and junction_probe())
        or not stat.S_ISDIR(status.st_mode)
    ):
        raise CompositionError(f"{owner} path is not a real directory: {path}.")


def load_bounded_json(path: Path) -> object:
    """Load bounded duplicate-free strict JSON from a stable regular file."""

    payload = read_bounded_bytes(path)
    try:
        text = payload.decode("utf-8")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_bounded_integer,
            parse_float=_parse_finite_float,
            parse_constant=_reject_nonfinite_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompositionError(f"Evidence JSON is invalid at {path}: {error}") from error
    _validate_json_shape(document)
    return document


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(read_bounded_bytes(path))


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    path.write_bytes(payload)


def _require_mapping(value: object, owner: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise CompositionError(f"{owner} must be a JSON object.")
    return value


def _require_positive_integer(value: object, owner: str) -> int:
    if type(value) is not int or value <= 0 or value > MAX_SAFE_INTEGER:
        raise CompositionError(f"{owner} must be a positive safe integer.")
    return value


def _require_commit(value: object, owner: str) -> str:
    if (
        not isinstance(value, str)
        or COMMIT_PATTERN.fullmatch(value) is None
        or value == "0" * 40
    ):
        raise CompositionError(f"{owner} must be a lowercase commit SHA.")
    return value


def _require_sha256(value: object, owner: str) -> str:
    if (
        not isinstance(value, str)
        or SHA256_PATTERN.fullmatch(value) is None
        or value == "0" * 64
    ):
        raise CompositionError(f"{owner} must be a nonzero lowercase SHA-256.")
    return value


def authenticate_workflow(
    *,
    role: str,
    expected_run_id: int,
    expected_source_head: str,
    run_metadata_path: Path,
    artifact_metadata_path: Path,
    download_root: Path,
) -> WorkflowIdentity:
    """Authenticate one exact-head successful workflow and its required artifacts."""

    configuration = ROLE_CONFIG[role]
    run = _require_mapping(load_bounded_json(run_metadata_path), f"{role} run")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (
        _require_positive_integer(run.get("id"), f"{role} run ID")
        != expected_run_id
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("path") != configuration["workflow"]
        or run.get("head_sha") != expected_source_head
        or not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY_NAME
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != REPOSITORY_NAME
    ):
        raise CompositionError(f"{role} workflow metadata is not the exact successful run.")

    response = _require_mapping(
        load_bounded_json(artifact_metadata_path), f"{role} artifact response"
    )
    artifacts = response.get("artifacts")
    if not isinstance(artifacts, list):
        raise CompositionError(f"{role} artifact response has no artifact array.")
    total_count = response.get("total_count")
    if (
        type(total_count) is not int
        or total_count != len(artifacts)
        or total_count > 100
    ):
        raise CompositionError(f"{role} artifact response is not one complete page.")
    by_name: dict[str, Mapping[str, object]] = {}
    all_ids: set[int] = set()
    for index, item in enumerate(artifacts):
        artifact = _require_mapping(item, f"{role} artifact {index}")
        name = artifact.get("name")
        artifact_id = _require_positive_integer(
            artifact.get("id"), f"{role} artifact {index} ID"
        )
        if artifact_id in all_ids:
            raise CompositionError(f"{role} artifact response repeats artifact ID {artifact_id}.")
        all_ids.add(artifact_id)
        if isinstance(name, str) and name in configuration["artifacts"]:
            if name in by_name:
                raise CompositionError(f"{role} artifact response repeats name {name!r}.")
            by_name[name] = artifact

    expected_names = configuration["artifacts"]
    if tuple(name for name in expected_names if name in by_name) != expected_names:
        missing = sorted(set(expected_names) - set(by_name))
        raise CompositionError(f"{role} workflow is missing artifacts: {missing}.")

    identities: list[ArtifactIdentity] = []
    for name in expected_names:
        artifact = by_name[name]
        workflow_run = artifact.get("workflow_run")
        digest = artifact.get("digest")
        if (
            artifact.get("expired") is not False
            or not isinstance(workflow_run, dict)
            or workflow_run.get("id") != expected_run_id
            or workflow_run.get("head_sha") != expected_source_head
            or not isinstance(digest, str)
            or not digest.startswith("sha256:")
        ):
            raise CompositionError(f"{role} artifact {name!r} has invalid provenance.")
        archive_sha256 = _require_sha256(
            digest.removeprefix("sha256:"), f"{role} artifact {name!r} digest"
        )
        artifact_root = download_root / name
        require_real_directory(artifact_root, f"downloaded {role} artifact {name!r}")
        identities.append(
            ArtifactIdentity(
                name=name,
                artifact_id=_require_positive_integer(
                    artifact.get("id"), f"{role} artifact {name!r} ID"
                ),
                digest=archive_sha256,
                root=artifact_root,
            )
        )
    return WorkflowIdentity(expected_run_id, expected_source_head, tuple(identities))


def _artifact(workflow: WorkflowIdentity, name: str) -> ArtifactIdentity:
    for artifact in workflow.artifacts:
        if artifact.name == name:
            return artifact
    raise CompositionError(f"Authenticated artifact {name!r} is unavailable.")


def verify_flat_checksum_manifest(root: Path, manifest_name: str) -> None:
    """Verify a canonical complete flat checksum manifest in O(n) time."""

    payload = read_bounded_bytes(root / manifest_name, maximum_bytes=1024 * 1024)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise CompositionError(f"{manifest_name} is not ASCII.") from error
    if not text.endswith("\n") or "\r" in text:
        raise CompositionError(f"{manifest_name} is not canonical LF text.")
    entries: dict[str, str] = {}
    ordered_names: list[str] = []
    for line in text.splitlines():
        match = MANIFEST_LINE_PATTERN.fullmatch(line)
        if match is None or match.group(2) in entries:
            raise CompositionError(f"{manifest_name} contains an invalid entry.")
        entries[match.group(2)] = match.group(1)
        ordered_names.append(match.group(2))
    if not ordered_names or ordered_names != sorted(ordered_names):
        raise CompositionError(f"{manifest_name} entries are not canonically ordered.")
    observed_files = set()
    for path in root.iterdir():
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise CompositionError(f"Coordinator artifact contains unsafe entry {path}.")
        observed_files.add(path.name)
    if observed_files != set(entries) | {manifest_name}:
        raise CompositionError(f"{manifest_name} does not enumerate the exact artifact.")
    for name, expected_digest in entries.items():
        if sha256_file(root / name) != expected_digest:
            raise CompositionError(f"{manifest_name} does not bind {name!r}.")


def _validate_projection(
    document: object,
    *,
    kind: str,
    corpus_sha256: str,
    implementation_sha256: str,
) -> list[Mapping[str, object]]:
    projection = _require_mapping(document, kind)
    if (
        set(projection)
        != {
            "schemaVersion",
            "kind",
            "corpusManifestSha256",
            "implementationManifestSha256",
            "variants",
        }
        or projection.get("schemaVersion") != "1"
        or projection.get("kind") != kind
        or projection.get("corpusManifestSha256") != corpus_sha256
        or projection.get("implementationManifestSha256")
        != implementation_sha256
    ):
        raise CompositionError(f"{kind} has the wrong exact typed contract.")
    variants = projection.get("variants")
    if not isinstance(variants, list) or len(variants) != len(VARIANT_IDS):
        raise CompositionError(f"{kind} has the wrong variant count.")
    typed = [_require_mapping(value, f"{kind} variant") for value in variants]
    if tuple(value.get("id") for value in typed) != VARIANT_IDS:
        raise CompositionError(f"{kind} has the wrong ordered variant IDs.")
    if any(set(value) != {"id", "value"} for value in typed):
        raise CompositionError(f"{kind} variants are not exact ID/value pairs.")
    return typed


def _copy_bound_reference(
    source: Path,
    stage_expected: Path,
    relative_path: object,
    expected_digest: object,
) -> None:
    canonical_path = PurePosixPath(relative_path) if isinstance(relative_path, str) else None
    if (
        canonical_path is None
        or not relative_path.startswith("expected/")
        or "\\" in relative_path
        or str(canonical_path) != relative_path
        or ".." in canonical_path.parts
        or canonical_path.is_absolute()
    ):
        raise CompositionError("Supporting evidence path is not canonical and contained.")
    digest = _require_sha256(expected_digest, f"reference to {relative_path}")
    payload = read_bounded_bytes(source)
    if sha256_bytes(payload) != digest:
        raise CompositionError(f"Raw supporting reference mismatch for {relative_path}.")
    destination = stage_expected.parent / relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)


def _workflow_document(workflow: WorkflowIdentity) -> dict[str, object]:
    return {
        "runId": workflow.run_id,
        "sourceHeadSha": workflow.source_head_sha,
        "artifacts": [
            {
                "name": artifact.name,
                "id": artifact.artifact_id,
                "digest": artifact.digest,
            }
            for artifact in workflow.artifacts
        ],
    }


def _projection_map(variants: Sequence[Mapping[str, object]]) -> dict[str, object]:
    return {str(value["id"]): value["value"] for value in variants}


def _admit_release(
    workflow: WorkflowIdentity,
    stage_expected: Path,
    corpus_sha256: str,
    implementation_sha256: str,
    research_root: Path,
) -> tuple[list[Mapping[str, object]], Path, Path, Path, Path]:
    cross = _artifact(workflow, "holdout-cross-platform").root
    verify_flat_checksum_manifest(cross, "cross-platform-checksums.sha256")
    projection_path = (
        cross / "sparse-experiment-release-composite-projection.json"
    )
    variants = _validate_projection(
        load_bounded_json(projection_path),
        kind=str(ROLE_CONFIG["release"]["projectionKind"]),
        corpus_sha256=corpus_sha256,
        implementation_sha256=implementation_sha256,
    )
    linux = _artifact(workflow, "holdout-linux").root
    windows = _artifact(workflow, "holdout-windows").root
    report_names = ("sarif-regress-holdout.json", "development-corpus-report.json")
    for name in report_names:
        cross_payload = read_bounded_bytes(cross / name)
        if (
            read_bounded_bytes(linux / name) != cross_payload
            or read_bounded_bytes(windows / name) != cross_payload
        ):
            raise CompositionError(f"Release report {name!r} is not cross-platform identical.")
    holdout_document = load_bounded_json(cross / report_names[0])
    development_document = load_bounded_json(cross / report_names[1])
    development = _require_mapping(development_document, "development corpus report")
    if development.get("passed") is not True or development.get("failures") != []:
        raise CompositionError("Development corpus release evidence is not green.")

    projector_tools = research_root / "tools"
    sys.path.insert(0, str(projector_tools))
    try:
        from project_release_evidence import project_release_evidence
    finally:
        sys.path.pop(0)
    projected_release = project_release_evidence(
        holdout_document,
        development_document,
        producer_order=PRODUCER_ORDER,
        relationships_per_producer=RELATIONSHIPS_PER_PRODUCER,
    )
    if projected_release is None:
        raise CompositionError("Release reports cannot be projected safely.")

    expected_paths = {
        "holdout": "expected/supporting/release/sarif-regress-holdout.json",
        "developmentCorpus": (
            "expected/supporting/release/development-corpus-report.json"
        ),
    }
    for variant in variants:
        value = _require_mapping(variant["value"], "release variant value")
        if set(value) != {"holdout", "developmentCorpus"}:
            raise CompositionError("Release projection has unexpected value fields.")
        holdout = _require_mapping(value.get("holdout"), "release holdout")
        development = _require_mapping(
            value.get("developmentCorpus"), "release development corpus"
        )
        semantic_value = {
            "holdout": {
                key: item
                for key, item in holdout.items()
                if key not in {"reportPath", "reportSha256"}
            },
            "developmentCorpus": {
                key: item
                for key, item in development.items()
                if key not in {"reportPath", "reportSha256"}
            },
        }
        if semantic_value != projected_release:
            raise CompositionError("Release projection disagrees with the exact reports.")
        if (
            holdout.get("reportPath") != expected_paths["holdout"]
            or development.get("reportPath") != expected_paths["developmentCorpus"]
        ):
            raise CompositionError("Release projection uses a noncanonical raw-report path.")
        _copy_bound_reference(
            cross / "sarif-regress-holdout.json",
            stage_expected,
            holdout.get("reportPath"),
            holdout.get("reportSha256"),
        )
        _copy_bound_reference(
            cross / "development-corpus-report.json",
            stage_expected,
            development.get("reportPath"),
            development.get("reportSha256"),
        )
    observations = cross / "sparse-experiment-observations.json"
    gates = cross / "sparse-experiment-gate-evidence.json"
    provenance = cross / "sparse-experiment-workflow-provenance.json"
    return variants, projection_path, observations, gates, provenance


def _admit_determinism(
    workflow: WorkflowIdentity,
    stage_expected: Path,
    corpus_sha256: str,
    implementation_sha256: str,
) -> tuple[list[Mapping[str, object]], Path]:
    cross = _artifact(workflow, "cross-platform-determinism").root
    verify_flat_checksum_manifest(cross, "checksums.sha256")
    projection_path = (
        cross / "sparse-experiment-determinism-composite-projection.json"
    )
    variants = _validate_projection(
        load_bounded_json(projection_path),
        kind=str(ROLE_CONFIG["determinism"]["projectionKind"]),
        corpus_sha256=corpus_sha256,
        implementation_sha256=implementation_sha256,
    )
    first_value = _require_mapping(variants[0]["value"], "determinism value")
    if set(first_value) != {
        "repeatedRunByteIdentical",
        "linuxWindowsByteIdentical",
        "linux",
        "windows",
        "comparison",
    }:
        raise CompositionError("Determinism projection has unexpected value fields.")
    for name in ("linux", "windows", "comparison"):
        reference = _require_mapping(first_value.get(name), f"determinism {name}")
        supporting_file = cross / f"sparse-experiment-determinism-{name}.json"
        expected_path = f"expected/supporting/determinism/{name}.json"
        if reference.get("artifactPath") != expected_path:
            raise CompositionError(
                f"Determinism {name} uses a noncanonical supporting path."
            )
        _copy_bound_reference(
            supporting_file,
            stage_expected,
            reference.get("artifactPath"),
            reference.get("artifactSha256"),
        )
        supporting_value = _require_mapping(
            load_bounded_json(supporting_file), f"determinism {name} supporting bytes"
        )
        if {
            key: value
            for key, value in reference.items()
            if key not in {"artifactPath", "artifactSha256"}
        } != supporting_value:
            raise CompositionError(f"Determinism {name} reference changes semantic bytes.")
    for variant in variants[1:]:
        if variant["value"] != variants[0]["value"]:
            raise CompositionError("Determinism variants disagree unexpectedly.")
    raw_payloads: dict[str, list[bytes]] = {"observations": [], "gates": []}
    for platform in ("linux", "windows"):
        platform_value = _require_mapping(first_value[platform], platform)
        platform_root = _artifact(workflow, f"determinism-{platform}").root
        sparse_root = platform_root / "sparse-determinism"
        require_real_directory(sparse_root, f"determinism {platform}")
        for run_number, digest_key in (
            (1, "firstOutputSha256"),
            (2, "secondOutputSha256"),
        ):
            run_root = sparse_root / f"run-{run_number}"
            require_real_directory(
                run_root, f"determinism {platform} run {run_number}"
            )
            require_real_directory(
                run_root / "observations",
                f"determinism {platform} run {run_number} observations",
            )
            require_real_directory(
                run_root / "evaluation",
                f"determinism {platform} run {run_number} evaluation",
            )
            observations = read_bounded_bytes(
                run_root / "observations" / "sparse-experiment-observations.json"
            )
            gates = read_bounded_bytes(
                run_root / "evaluation" / "sparse-experiment-gate-evidence.json"
            )
            raw_payloads["observations"].append(observations)
            raw_payloads["gates"].append(gates)
            expected_digest = _require_sha256(
                platform_value.get(digest_key),
                f"determinism {platform} {digest_key}",
            )
            if sha256_bytes(gates) != expected_digest:
                raise CompositionError(
                    f"Determinism {platform} run {run_number} gate hash is unbound."
                )
            if run_number == 1:
                coordinator_prefix = f"sparse-{platform}-"
                if (
                    read_bounded_bytes(
                        cross
                        / f"{coordinator_prefix}sparse-experiment-observations.json"
                    )
                    != observations
                    or read_bounded_bytes(
                        cross
                        / f"{coordinator_prefix}sparse-experiment-gate-evidence.json"
                    )
                    != gates
                ):
                    raise CompositionError(
                        f"Determinism {platform} coordinator bytes differ from run 1."
                    )
    for output_name, payloads in raw_payloads.items():
        if any(payload != payloads[0] for payload in payloads[1:]):
            raise CompositionError(
                f"Determinism {output_name} bytes differ across runs or platforms."
            )
    return variants, projection_path


def _admit_resources(
    workflow: WorkflowIdentity,
    stage_expected: Path,
    corpus_sha256: str,
    implementation_sha256: str,
) -> tuple[list[Mapping[str, object]], Path, Path]:
    cross = _artifact(workflow, "benchmark-cross-platform").root
    verify_flat_checksum_manifest(cross, "checksums.sha256")
    values_path = cross / "sparse-experiment-resource-values.json"
    projection_path = cross / "sparse-experiment-resource-projection.json"
    observations_path = cross / "sparse-experiment-resource-observations.json"
    values_document = _require_mapping(
        load_bounded_json(values_path), "full resource values"
    )
    expected_values_header = {
        "schemaVersion": "1",
        "kind": "sparse-experiment-resource-values/v1",
        "corpusManifestSha256": corpus_sha256,
        "implementationManifestSha256": implementation_sha256,
    }
    if set(values_document) != set(expected_values_header) | {"variants"} or any(
        values_document.get(key) != value
        for key, value in expected_values_header.items()
    ):
        raise CompositionError("Full resource values do not bind the admitted source.")
    resource_variants = values_document.get("variants")
    if not isinstance(resource_variants, list):
        raise CompositionError("Full resource values have no variants.")
    typed_variants = [
        _require_mapping(value, "resource variant") for value in resource_variants
    ]
    if (
        tuple(value.get("id") for value in typed_variants) != VARIANT_IDS
        or any(set(value) != {"id", "value"} for value in typed_variants)
    ):
        raise CompositionError("Full resource values have the wrong variant order.")
    projection_variants = _validate_projection(
        load_bounded_json(projection_path),
        kind=str(ROLE_CONFIG["resources"]["projectionKind"]),
        corpus_sha256=corpus_sha256,
        implementation_sha256=implementation_sha256,
    )
    for full, projected in zip(typed_variants, projection_variants, strict=True):
        full_value = _require_mapping(full.get("value"), "resource value")
        if set(full_value) != {
            "withinDocumentedLimits",
            "sourceContextProjectionBenchmarked",
            "cells",
            "evidencePath",
            "evidenceSha256",
        }:
            raise CompositionError("Full resource value has unexpected fields.")
        projected_value = _require_mapping(projected.get("value"), "resource projection")
        expected_projection = {
            key: full_value.get(key)
            for key in (
                "withinDocumentedLimits",
                "sourceContextProjectionBenchmarked",
                "evidencePath",
                "evidenceSha256",
            )
        }
        if projected_value != expected_projection:
            raise CompositionError("Stable resource projection disagrees with full values.")
        if (
            full_value.get("evidencePath")
            != "expected/sparse-experiment-resource-observations.json"
        ):
            raise CompositionError(
                "Resource evidence uses a noncanonical observation path."
            )
        _copy_bound_reference(
            observations_path,
            stage_expected,
            full_value.get("evidencePath"),
            full_value.get("evidenceSha256"),
        )
        cells = full_value.get("cells")
        if not isinstance(cells, list) or len(cells) != 12:
            raise CompositionError("Resource variant does not contain the 12-cell matrix.")
        identities = [
            (
                cell.get("operatingSystem"),
                cell.get("findingCount"),
                cell.get("dataset"),
            )
            for cell in cells
            if isinstance(cell, dict)
        ]
        if identities != list(RESOURCE_CELL_KEYS):
            raise CompositionError("Resource cells have the wrong ordered identities.")
        for cell_value in cells:
            cell = _require_mapping(cell_value, "resource cell")
            operating_system = cell.get("operatingSystem")
            finding_count = cell.get("findingCount")
            dataset = cell.get("dataset")
            platform = {"ubuntu": "linux", "windows": "windows"}.get(
                operating_system
            )
            if (
                platform is None
                or finding_count not in {1_000, 10_000, 100_000}
                or dataset not in {"unique", "pathological"}
            ):
                raise CompositionError("Resource cell identity is invalid.")
            raw = _artifact(
                workflow,
                f"benchmark-{finding_count}-{dataset}-{platform}",
            ).root / "report.json"
            expected_path = (
                "expected/supporting/resources/"
                f"{operating_system}-{finding_count}-{dataset}.json"
            )
            if cell.get("artifactPath") != expected_path:
                raise CompositionError("Resource cell uses a noncanonical raw-report path.")
            _copy_bound_reference(
                raw,
                stage_expected,
                cell.get("artifactPath"),
                cell.get("artifactSha256"),
            )
    return typed_variants, projection_path, observations_path


def _copy_file(source: Path, destination: Path) -> None:
    payload = read_bounded_bytes(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(payload)


def _copy_existing_expected(source: Path, destination: Path) -> None:
    if not source.is_dir() or source.is_symlink():
        raise CompositionError("Committed expected evidence directory is unsafe.")
    for path in sorted(source.rglob("*"), key=lambda value: value.as_posix()):
        relative = path.relative_to(source)
        target = destination / relative
        status = path.lstat()
        if path.is_symlink():
            raise CompositionError(f"Expected evidence contains a link: {relative}.")
        if stat.S_ISDIR(status.st_mode):
            target.mkdir(parents=True, exist_ok=True)
        elif stat.S_ISREG(status.st_mode):
            if path.name not in {
                "checksums.sha256",
                "sparse-experiment-limitation.json",
            }:
                _copy_file(path, target)
        else:
            raise CompositionError(f"Expected evidence contains a special file: {relative}.")
    supporting = destination / "supporting"
    if supporting.exists():
        shutil.rmtree(supporting)


def _write_checksum_manifest(expected_root: Path) -> None:
    files = sorted(
        (
            path
            for path in expected_root.rglob("*")
            if path.is_file() and path.name != "checksums.sha256"
        ),
        key=lambda path: path.relative_to(expected_root).as_posix(),
    )
    lines = []
    for path in files:
        if path.is_symlink():
            raise CompositionError("Candidate expected evidence contains a link.")
        lines.append(
            f"{sha256_file(path)}  {path.relative_to(expected_root).as_posix()}\n"
        )
    (expected_root / "checksums.sha256").write_bytes("".join(lines).encode("ascii"))


def _typed_reference(kind: str, relative_path: str, path: Path) -> dict[str, object]:
    return {"kind": kind, "path": relative_path, "sha256": sha256_file(path)}


def _supporting_document(
    role: str,
    workflow: WorkflowIdentity,
    corpus_sha256: str,
    implementation_sha256: str,
    projection_relative_path: str,
    projection_path: Path,
    variants: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "kind": ROLE_CONFIG[role]["kind"],
        "corpusManifestSha256": corpus_sha256,
        "implementationManifestSha256": implementation_sha256,
        "workflow": _workflow_document(workflow),
        "projectionPath": projection_relative_path,
        "projectionSha256": sha256_file(projection_path),
        "variants": list(variants),
    }


def compose_evidence(
    *,
    repository_root: Path,
    metadata_root: Path,
    release_root: Path,
    determinism_root: Path,
    resources_root: Path,
    release_run_id: int,
    determinism_run_id: int,
    resources_run_id: int,
    source_head_sha: str,
    output_root: Path,
) -> None:
    """Authenticate and atomically assemble a deterministic v2 limitation report."""

    source_head_sha = _require_commit(source_head_sha, "source head")
    repository_root = repository_root.resolve()
    metadata_root = metadata_root.resolve()
    release_root = release_root.resolve()
    determinism_root = determinism_root.resolve()
    resources_root = resources_root.resolve()
    output_root = output_root.resolve()
    run_ids = (
        _require_positive_integer(release_run_id, "release run ID"),
        _require_positive_integer(determinism_run_id, "determinism run ID"),
        _require_positive_integer(resources_run_id, "resources run ID"),
    )
    if len(set(run_ids)) != len(run_ids):
        raise CompositionError("Supporting roles must use distinct workflow runs.")
    if output_root.exists():
        raise CompositionError("Output root must not already exist.")
    research_root = repository_root / "validation/research/sparse-sarif"
    expected_source = research_root / "expected"
    corpus_sha256 = sha256_file(research_root / "manifest.json")
    implementation_sha256 = sha256_file(
        research_root / "experiment-implementation-manifest.json"
    )

    workflows = {
        role: authenticate_workflow(
            role=role,
            expected_run_id=run_id,
            expected_source_head=source_head_sha,
            run_metadata_path=metadata_root / f"{role}-run.json",
            artifact_metadata_path=metadata_root / f"{role}-artifacts.json",
            download_root=download_root,
        )
        for role, run_id, download_root in (
            ("release", release_run_id, release_root),
            ("determinism", determinism_run_id, determinism_root),
            ("resources", resources_run_id, resources_root),
        )
    }
    all_artifact_ids = [
        artifact.artifact_id
        for workflow in workflows.values()
        for artifact in workflow.artifacts
    ]
    if len(all_artifact_ids) != len(set(all_artifact_ids)):
        raise CompositionError("Supporting roles reuse a GitHub artifact ID.")

    output_parent = output_root.parent.resolve()
    output_parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output_root.name}-", dir=output_parent)
    )
    try:
        stage_expected = temporary / "expected"
        stage_expected.mkdir()
        _copy_existing_expected(expected_source, stage_expected)
        for role in ("release", "determinism", "resources"):
            for metadata_kind in ("run", "artifacts"):
                name = f"{role}-{metadata_kind}.json"
                _copy_file(
                    metadata_root / name,
                    stage_expected / "supporting/github" / name,
                )

        release_variants, release_projection, observations, gates, provenance = (
            _admit_release(
                workflows["release"],
                stage_expected,
                corpus_sha256,
                implementation_sha256,
                research_root,
            )
        )
        determinism_variants, determinism_projection = _admit_determinism(
            workflows["determinism"],
            stage_expected,
            corpus_sha256,
            implementation_sha256,
        )
        resource_variants, resource_projection, resource_observations = (
            _admit_resources(
                workflows["resources"],
                stage_expected,
                corpus_sha256,
                implementation_sha256,
            )
        )

        canonical_files = {
            "expected/sparse-experiment-observations.json": observations,
            "expected/sparse-experiment-gate-evidence.json": gates,
            "expected/sparse-experiment-workflow-provenance.json": provenance,
            "expected/sparse-experiment-resource-observations.json": (
                resource_observations
            ),
            "expected/projections/sparse-experiment-release-composite-projection.json": (
                release_projection
            ),
            "expected/projections/sparse-experiment-determinism-composite-projection.json": (
                determinism_projection
            ),
            "expected/projections/sparse-experiment-resource-projection.json": (
                resource_projection
            ),
        }
        for relative, source in canonical_files.items():
            _copy_file(source, temporary / relative)

        supporting_specs = {
            "release": (
                release_variants,
                (
                    "expected/projections/"
                    "sparse-experiment-release-composite-projection.json"
                ),
                release_projection,
            ),
            "determinism": (
                determinism_variants,
                (
                    "expected/projections/"
                    "sparse-experiment-determinism-composite-projection.json"
                ),
                determinism_projection,
            ),
            "resources": (
                resource_variants,
                "expected/projections/sparse-experiment-resource-projection.json",
                resource_projection,
            ),
        }
        supporting_paths: dict[str, Path] = {}
        for role, (variants, projection_relative, projection_source) in supporting_specs.items():
            relative = f"expected/sparse-experiment-{role}-evidence.json"
            path = temporary / relative
            write_json(
                path,
                _supporting_document(
                    role,
                    workflows[role],
                    corpus_sha256,
                    implementation_sha256,
                    projection_relative,
                    projection_source,
                    variants,
                ),
            )
            supporting_paths[role] = path

        observations_document = _require_mapping(
            load_bounded_json(temporary / "expected/sparse-experiment-observations.json"),
            "experiment observations",
        )
        gates_document = _require_mapping(
            load_bounded_json(temporary / "expected/sparse-experiment-gate-evidence.json"),
            "experiment gates",
        )
        observation_variants = observations_document.get("variants")
        gate_variants = gates_document.get("variants")
        if not isinstance(observation_variants, list) or not isinstance(
            gate_variants, list
        ):
            raise CompositionError("Observation or gate evidence has no variant array.")
        observation_map = {
            str(value["id"]): _require_mapping(value, "observation variant")
            for value in observation_variants
            if isinstance(value, dict) and isinstance(value.get("id"), str)
        }
        gate_map = {
            str(value["id"]): _require_mapping(value, "gate variant")
            for value in gate_variants
            if isinstance(value, dict) and isinstance(value.get("id"), str)
        }
        if tuple(observation_map) != VARIANT_IDS or tuple(gate_map) != VARIANT_IDS:
            raise CompositionError("Observation/gate variant topology is not predeclared.")
        release_map = _projection_map(release_variants)
        determinism_map = _projection_map(determinism_variants)
        resource_map = _projection_map(resource_variants)

        scanner_tools = research_root / "tools"
        sys.path.insert(0, str(scanner_tools))
        try:
            from scan_contamination import FIXED_EXPERIMENT_GATES, Scanner
        finally:
            sys.path.pop(0)

        report_variants: list[dict[str, object]] = []
        for variant_id in VARIANT_IDS:
            observation = observation_map[variant_id]
            gate = gate_map[variant_id]
            by_family = gate.get("byFamily")
            if not isinstance(by_family, list):
                raise CompositionError(f"Gate variant {variant_id} has no family metrics.")
            variant = {
                "id": variant_id,
                "description": VARIANT_DESCRIPTIONS[variant_id],
                "metrics": {
                    "aggregate": gate.get("metrics"),
                    "byFamily": [
                        {"familyId": family.get("familyId"), **family.get("metrics", {})}
                        for family in by_family
                        if isinstance(family, dict)
                        and isinstance(family.get("metrics"), dict)
                    ],
                },
                "classification": gate.get("classification"),
                "lifecycle": gate.get("lifecycle"),
                "releaseEvidence": release_map[variant_id],
                "productionApplicability": gate.get("productionApplicability"),
                "scenarios": gate.get("scenarios"),
                "ambiguity": gate.get("ambiguity"),
                "ingestion": gate.get("ingestion"),
                "security": gate.get("security"),
                "determinism": determinism_map[variant_id],
                "resources": resource_map[variant_id],
            }
            computed = Scanner._computed_gate_bindings(variant)
            if computed is None:
                raise CompositionError(f"Variant {variant_id} has inconsistent bound evidence.")
            variant["gateProjection"] = computed
            report_variants.append(variant)

        report = {
            "schemaVersion": "2",
            "corpusManifestSha256": corpus_sha256,
            "evidence": {
                "observations": _typed_reference(
                    "sparse-experiment-observations/v1",
                    "expected/sparse-experiment-observations.json",
                    temporary / "expected/sparse-experiment-observations.json",
                ),
                "gates": _typed_reference(
                    "sparse-experiment-gates/v1",
                    "expected/sparse-experiment-gate-evidence.json",
                    temporary / "expected/sparse-experiment-gate-evidence.json",
                ),
                **{
                    role: _typed_reference(
                        str(ROLE_CONFIG[role]["kind"]),
                        f"expected/sparse-experiment-{role}-evidence.json",
                        supporting_paths[role],
                    )
                    for role in ("release", "determinism", "resources")
                },
            },
            "implementation": {
                "name": "SarifRegress sparse experiment harness",
                "version": "sparse-experiment/v2",
                "manifestPath": "experiment-implementation-manifest.json",
                "manifestSha256": implementation_sha256,
            },
            "fixedGates": FIXED_EXPERIMENT_GATES,
            "variants": report_variants,
            "selectedVariant": None,
            "decision": "document-limitation",
            "reasons": [
                "No predeclared variant satisfies every fixed quality, safety, "
                "determinism, and resource gate."
            ],
        }
        if all(Scanner._variant_projection_passes_gates(value) for value in report_variants):
            raise CompositionError("A limitation report cannot hide an all-green variant matrix.")
        write_json(stage_expected / "experiment-report.json", report)
        _write_checksum_manifest(stage_expected)
        os.replace(temporary, output_root)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _positive_run_id(value: str) -> int:
    if re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise argparse.ArgumentTypeError("run ID must be a positive decimal integer")
    parsed = int(value)
    if parsed > MAX_SAFE_INTEGER:
        raise argparse.ArgumentTypeError("run ID exceeds the interoperable safe range")
    return parsed


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--metadata-root", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--determinism-root", type=Path, required=True)
    parser.add_argument("--resources-root", type=Path, required=True)
    parser.add_argument("--release-run-id", type=_positive_run_id, required=True)
    parser.add_argument("--determinism-run-id", type=_positive_run_id, required=True)
    parser.add_argument("--resources-run-id", type=_positive_run_id, required=True)
    parser.add_argument("--source-head", required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    try:
        compose_evidence(
            repository_root=arguments.repository_root.resolve(),
            metadata_root=arguments.metadata_root.resolve(),
            release_root=arguments.release_root.resolve(),
            determinism_root=arguments.determinism_root.resolve(),
            resources_root=arguments.resources_root.resolve(),
            release_run_id=arguments.release_run_id,
            determinism_run_id=arguments.determinism_run_id,
            resources_run_id=arguments.resources_run_id,
            source_head_sha=arguments.source_head,
            output_root=arguments.output_root.resolve(),
        )
    except CompositionError as error:
        print(f"Sparse evidence composition refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
