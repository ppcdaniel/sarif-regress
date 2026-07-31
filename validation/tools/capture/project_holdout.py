#!/usr/bin/env python3
"""Project authentic producer SARIF into deterministic holdout cases.

The raw captures remain untouched. This adapter locates each finding through the
immediately preceding HOLDOUT marker in controlled source, applies only the
documented path/version/message/fingerprint projections, and derives labels from
the case plan without consulting SarifRegress output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, Mapping, Sequence
from urllib.parse import unquote, urlparse


MAX_JSON_BYTES: Final = 16 * 1024 * 1024
MARKER_PATTERN: Final = re.compile(
    r"^\s*(?:#|//)\s*HOLDOUT:(?P<semantic_id>[a-z0-9-]+)\s*$"
)
SUPPORTED_PRODUCERS: Final = frozenset({"semgrep", "gitleaks", "pmd"})
SUPPORTED_CLASSIFICATIONS: Final = frozenset(
    {"unchanged", "moved", "modified"}
)
SUPPORTED_PRESENCE: Final = frozenset({"both", "baseline", "candidate"})
SUPPORTED_SCENARIOS: Final = frozenset(
    {
        "exact",
        "line-shift",
        "moved",
        "renamed",
        "message-modified",
        "resolved",
        "new",
        "ambiguous",
    }
)
SCENARIO_COUNTS: Final = {
    "exact": 5,
    "line-shift": 5,
    "moved": 5,
    "renamed": 5,
    "message-modified": 5,
    "resolved": 3,
    "new": 3,
    "ambiguous": 2,
}


class ProjectionError(RuntimeError):
    """Raised when a capture cannot be projected without guessing."""


@dataclass(frozen=True, slots=True)
class PlanEntry:
    """One source-authored ground-truth relationship."""

    semantic_id: str
    scenario: str
    presence: str
    classification: str | None


@dataclass(frozen=True, slots=True)
class CasePlan:
    """Validated producer case-plan contract."""

    producer: str
    producer_version: str
    candidate_version_projection: str
    projection_version: str
    entries: tuple[PlanEntry, ...]

    @property
    def entries_by_id(self) -> Mapping[str, PlanEntry]:
        """Return an ordinal-keyed lookup without changing plan order."""

        return {entry.semantic_id: entry for entry in self.entries}


@dataclass(frozen=True, slots=True)
class LocatedResult:
    """A raw SARIF result mapped to controlled source."""

    semantic_id: str
    raw_result_index: int
    source_relative_path: PurePosixPath
    result: dict[str, Any]


def _read_bounded_json(path: Path) -> Any:
    """Read one bounded UTF-8 JSON document."""

    with path.open("rb") as stream:
        payload = stream.read(MAX_JSON_BYTES + 1)
    if len(payload) > MAX_JSON_BYTES:
        raise ProjectionError(
            f"{path} exceeds the {MAX_JSON_BYTES}-byte capture bound."
        )
    if payload.startswith(b"\xef\xbb\xbf"):
        raise ProjectionError(f"{path} must be UTF-8 without a BOM.")
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProjectionError(f"{path} is not valid UTF-8 JSON: {error}") from error


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProjectionError(f"{context} must be a JSON object.")
    return value


def _require_array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProjectionError(f"{context} must be a JSON array.")
    return value


def _require_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProjectionError(f"{context} must be a non-empty string.")
    return value


def _parse_plan(path: Path) -> CasePlan:
    document = _require_object(_read_bounded_json(path), str(path))
    expected_keys = {
        "schemaVersion",
        "producer",
        "producerVersion",
        "candidateVersionProjection",
        "projectionVersion",
        "entries",
    }
    if set(document) != expected_keys:
        raise ProjectionError(
            f"{path} keys differ from the case-plan v1 contract."
        )
    if document["schemaVersion"] != "1":
        raise ProjectionError(f"{path} schemaVersion must be '1'.")

    producer = _require_string(document["producer"], f"{path}: producer")
    if producer not in SUPPORTED_PRODUCERS:
        raise ProjectionError(f"{path} has unsupported producer {producer!r}.")
    producer_version = _require_string(
        document["producerVersion"], f"{path}: producerVersion"
    )
    candidate_version = _require_string(
        document["candidateVersionProjection"],
        f"{path}: candidateVersionProjection",
    )
    projection_version = _require_string(
        document["projectionVersion"], f"{path}: projectionVersion"
    )
    if projection_version != "holdout-projection/v1":
        raise ProjectionError(f"{path} has an unsupported projection version.")

    entries: list[PlanEntry] = []
    semantic_ids: set[str] = set()
    scenario_counts = {scenario: 0 for scenario in SUPPORTED_SCENARIOS}
    for index, raw_entry in enumerate(
        _require_array(document["entries"], f"{path}: entries")
    ):
        entry = _require_object(raw_entry, f"{path}: entries[{index}]")
        allowed_keys = {"semanticId", "scenario", "presence", "classification"}
        if not set(entry).issubset(allowed_keys):
            raise ProjectionError(
                f"{path}: entries[{index}] has unsupported fields."
            )
        semantic_id = _require_string(
            entry.get("semanticId"), f"{path}: entries[{index}].semanticId"
        )
        if not semantic_id.startswith(f"{producer}-"):
            raise ProjectionError(
                f"{path}: {semantic_id!r} is not producer-namespaced."
            )
        if semantic_id in semantic_ids:
            raise ProjectionError(f"{path}: duplicate semantic ID {semantic_id}.")
        semantic_ids.add(semantic_id)

        scenario = _require_string(
            entry.get("scenario"), f"{path}: entries[{index}].scenario"
        )
        if scenario not in SUPPORTED_SCENARIOS:
            raise ProjectionError(f"{path}: unsupported scenario {scenario!r}.")
        scenario_counts[scenario] += 1

        presence = _require_string(
            entry.get("presence"), f"{path}: entries[{index}].presence"
        )
        if presence not in SUPPORTED_PRESENCE:
            raise ProjectionError(f"{path}: unsupported presence {presence!r}.")

        classification_value = entry.get("classification")
        classification = (
            _require_string(
                classification_value,
                f"{path}: entries[{index}].classification",
            )
            if classification_value is not None
            else None
        )
        if (
            classification is not None
            and classification not in SUPPORTED_CLASSIFICATIONS
        ):
            raise ProjectionError(
                f"{path}: unsupported classification {classification!r}."
            )
        if (
            presence == "both"
            and scenario != "ambiguous"
            and classification is None
        ):
            raise ProjectionError(
                f"{path}: paired entry {semantic_id} lacks a classification."
            )
        if (
            (presence != "both" or scenario == "ambiguous")
            and classification is not None
        ):
            raise ProjectionError(
                f"{path}: {semantic_id} must not declare a pair classification."
            )
        entries.append(
            PlanEntry(semantic_id, scenario, presence, classification)
        )

    if scenario_counts != SCENARIO_COUNTS:
        raise ProjectionError(
            f"{path}: scenario counts are {scenario_counts}, expected "
            f"{SCENARIO_COUNTS}."
        )
    return CasePlan(
        producer,
        producer_version,
        candidate_version,
        projection_version,
        tuple(entries),
    )


def _physical_location(result: Mapping[str, Any], context: str) -> dict[str, Any]:
    locations = _require_array(result.get("locations"), f"{context}.locations")
    if not locations:
        raise ProjectionError(f"{context}.locations must not be empty.")
    location = _require_object(locations[0], f"{context}.locations[0]")
    return _require_object(
        location.get("physicalLocation"),
        f"{context}.locations[0].physicalLocation",
    )


def _source_path_from_uri(
    uri: str, source_root: Path
) -> tuple[Path, PurePosixPath]:
    parsed = urlparse(uri)
    if parsed.scheme and parsed.scheme.lower() != "file":
        raise ProjectionError(f"Unsupported non-file artifact URI {uri!r}.")

    if parsed.scheme.lower() == "file":
        decoded_path = unquote(parsed.path)
        candidates = [Path(decoded_path)]
    else:
        normalized = unquote(uri).replace("\\", "/").removeprefix("./")
        raw_path = Path(normalized)
        candidates = [source_root / raw_path]
        parts = tuple(
            part for part in PurePosixPath(normalized).parts if part != "."
        )
        candidates.extend(
            source_root.joinpath(*parts[index:])
            for index in range(1, len(parts))
        )

    resolved_root = source_root.resolve(strict=True)
    matches: dict[Path, PurePosixPath] = {}
    for candidate in candidates:
        try:
            resolved_candidate = candidate.resolve(strict=True)
            relative = resolved_candidate.relative_to(resolved_root)
        except (FileNotFoundError, RuntimeError, ValueError):
            continue
        if not resolved_candidate.is_file():
            continue
        matches[resolved_candidate] = PurePosixPath(relative.as_posix())

    if len(matches) != 1:
        raise ProjectionError(
            f"Artifact URI {uri!r} resolved to {len(matches)} controlled files."
        )
    resolved_path, relative_path = next(iter(matches.items()))
    return resolved_path, relative_path


def _semantic_marker(source_path: Path, start_line: int) -> str:
    if start_line < 2:
        raise ProjectionError(
            f"{source_path}:{start_line} has no preceding marker line."
        )
    source_bytes = source_path.read_bytes()
    if len(source_bytes) > MAX_JSON_BYTES:
        raise ProjectionError(f"{source_path} exceeds the source-file bound.")
    try:
        source_lines = source_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ProjectionError(f"{source_path} is not valid UTF-8.") from error
    if start_line > len(source_lines):
        raise ProjectionError(
            f"{source_path}:{start_line} exceeds the controlled source."
        )
    marker = MARKER_PATTERN.fullmatch(source_lines[start_line - 2])
    if marker is None:
        raise ProjectionError(
            f"{source_path}:{start_line - 1} is not an exact HOLDOUT marker."
        )
    return marker.group("semantic_id")


def _assert_marker_absent_from_snippet(
    physical_location: Mapping[str, Any], context: str
) -> None:
    region = physical_location.get("region")
    if region is None:
        return
    region_object = _require_object(region, f"{context}.region")
    snippet = region_object.get("snippet")
    if snippet is None:
        return
    snippet_object = _require_object(snippet, f"{context}.region.snippet")
    for field in ("text", "markdown"):
        value = snippet_object.get(field)
        if isinstance(value, str) and "HOLDOUT:" in value:
            raise ProjectionError(
                f"{context}.region.snippet includes its audit marker."
            )


def _locate_results(
    document: dict[str, Any],
    source_root: Path,
    side: str,
    plan: CasePlan,
) -> tuple[dict[str, Any], list[LocatedResult]]:
    if document.get("version") != "2.1.0":
        raise ProjectionError(f"{side} capture is not SARIF 2.1.0.")
    runs = _require_array(document.get("runs"), f"{side}.runs")
    if len(runs) != 1:
        raise ProjectionError(f"{side} capture must contain exactly one run.")
    run = _require_object(runs[0], f"{side}.runs[0]")
    raw_results = _require_array(run.get("results"), f"{side}.runs[0].results")

    located: list[LocatedResult] = []
    observed_ids: set[str] = set()
    for result_index, raw_result in enumerate(raw_results):
        context = f"{side}.runs[0].results[{result_index}]"
        result = _require_object(raw_result, context)
        physical = _physical_location(result, context)
        artifact = _require_object(
            physical.get("artifactLocation"),
            f"{context}.locations[0].physicalLocation.artifactLocation",
        )
        uri = _require_string(
            artifact.get("uri"),
            f"{context}.locations[0].physicalLocation.artifactLocation.uri",
        )
        region = _require_object(
            physical.get("region"),
            f"{context}.locations[0].physicalLocation.region",
        )
        start_line = region.get("startLine")
        if not isinstance(start_line, int) or isinstance(start_line, bool):
            raise ProjectionError(
                f"{context}.region.startLine must be an integer."
            )

        source_path, source_relative_path = _source_path_from_uri(
            uri, source_root
        )
        semantic_id = _semantic_marker(source_path, start_line)
        if semantic_id in observed_ids:
            raise ProjectionError(
                f"{side} capture maps multiple results to {semantic_id}."
            )
        observed_ids.add(semantic_id)
        if semantic_id not in plan.entries_by_id:
            raise ProjectionError(
                f"{side} capture contains unplanned marker {semantic_id}."
            )
        _assert_marker_absent_from_snippet(physical, context)
        located.append(
            LocatedResult(
                semantic_id,
                result_index,
                source_relative_path,
                result,
            )
        )

    expected_ids = {
        entry.semantic_id
        for entry in plan.entries
        if entry.presence in {"both", side}
    }
    if observed_ids != expected_ids:
        missing = sorted(expected_ids - observed_ids)
        unexpected = sorted(observed_ids - expected_ids)
        raise ProjectionError(
            f"{side} capture/plan mismatch; missing={missing}, "
            f"unexpected={unexpected}."
        )
    return run, located


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _project_result(
    located: LocatedResult,
    side: str,
    plan: CasePlan,
) -> dict[str, Any]:
    entry = plan.entries_by_id[located.semantic_id]
    context = f"{side}:{located.semantic_id}"
    result = located.result
    physical = _physical_location(result, context)
    artifact = _require_object(
        physical.get("artifactLocation"), f"{context}.artifactLocation"
    )
    original_uri = _require_string(
        artifact.get("uri"), f"{context}.artifactLocation.uri"
    )
    applied_mutations: list[str] = []
    selected_path_projection = (
        located.semantic_id == f"{plan.producer}-line-shift-05"
    )
    if selected_path_projection:
        projected_root = (
            f"file:///opt/sarif-regress-holdout/{plan.producer}/baseline/"
            if side == "baseline"
            else f"file:///C:/sarif-regress-holdout/{plan.producer}/candidate/"
        )
        artifact["uri"] = (
            projected_root + located.source_relative_path.as_posix()
        )
        artifact.pop("uriBaseId", None)
        applied_mutations.append("path/windows-posix-rebase-v1")
    else:
        parsed_original_uri = urlparse(original_uri)
        if parsed_original_uri.scheme.lower() == "file":
            # PMD's SARIF formatter emits absolute file URIs even when its
            # relativize option is supplied. The controlled source resolver has
            # already proven containment, so remove only this ambient checkout
            # prefix from the deterministic evaluation projection.
            artifact["uri"] = located.source_relative_path.as_posix()
            artifact.pop("uriBaseId", None)
            applied_mutations.append("path/ambient-checkout-removal-v1")
        else:
            normalized_original_uri = (
                unquote(original_uri).replace("\\", "/").removeprefix("./")
            )
            if (
                normalized_original_uri
                != located.source_relative_path.as_posix()
            ):
                raise ProjectionError(
                    f"{context} must resolve to its producer-emitted relative "
                    f"source URI; found {original_uri!r}."
                )

    message = _require_object(result.get("message"), f"{context}.message")
    original_message = _require_string(
        message.get("text"), f"{context}.message.text"
    )
    if side == "candidate" and entry.scenario == "message-modified":
        message["text"] = (
            f"{original_message} "
            "[controlled candidate wording change]"
        )
        applied_mutations.append("message/candidate-controlled-change-v1")

    fingerprint_fields = {
        name: result[name]
        for name in ("fingerprints", "partialFingerprints")
        if name in result
    }
    if entry.scenario == "exact" and located.semantic_id.endswith("-03"):
        result.pop("fingerprints", None)
        result.pop("partialFingerprints", None)
        applied_mutations.append("fingerprint/ensured-missing-v1")
    elif entry.scenario == "ambiguous":
        result.pop("fingerprints", None)
        result["partialFingerprints"] = {
            "holdout/controlledFingerprint/v1": (
                f"{plan.producer}-ambiguous-shared"
            )
        }
        applied_mutations.append("fingerprint/controlled-duplicate-v1")

    original_fingerprints_sha256 = (
        _sha256_text(
            json.dumps(
                fingerprint_fields,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        if fingerprint_fields
        else None
    )
    return {
        "semanticId": located.semantic_id,
        "rawResultIndex": located.raw_result_index,
        "sourcePath": located.source_relative_path.as_posix(),
        "originalArtifactUriSha256": _sha256_text(original_uri),
        "projectedArtifactUri": artifact["uri"],
        "originalMessageSha256": _sha256_text(original_message),
        "originalFingerprintsSha256": original_fingerprints_sha256,
        "appliedMutations": applied_mutations,
    }


def _project_candidate_version(
    run: dict[str, Any], plan: CasePlan
) -> dict[str, Any]:
    tool = _require_object(run.get("tool"), "candidate.runs[0].tool")
    driver = _require_object(tool.get("driver"), "candidate.runs[0].tool.driver")
    original_versions = {
        field: driver[field]
        for field in ("semanticVersion", "version")
        if isinstance(driver.get(field), str) and driver[field]
    }
    if not original_versions:
        raise ProjectionError(
            "Candidate producer driver does not contain version metadata."
        )
    serialized_versions = json.dumps(
        original_versions,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    for field in original_versions:
        driver[field] = plan.candidate_version_projection

    return {
        "mutation": "producer-version/candidate-controlled-change-v1",
        "originalVersionMetadataSha256": _sha256_text(serialized_versions),
        "projectedVersion": plan.candidate_version_projection,
        "fields": sorted(original_versions),
    }


def _project_capture(
    raw_path: Path,
    source_root: Path,
    side: str,
    plan: CasePlan,
) -> tuple[dict[str, Any], Mapping[str, int], dict[str, Any]]:
    document = _require_object(_read_bounded_json(raw_path), str(raw_path))
    run, located_results = _locate_results(document, source_root, side, plan)
    located_results.sort(key=lambda item: item.semantic_id)
    result_audit: list[dict[str, Any]] = []
    for projected_index, located in enumerate(located_results):
        audit_entry = _project_result(located, side, plan)
        audit_entry["projectedResultIndex"] = projected_index
        result_audit.append(audit_entry)
    run["results"] = [item.result for item in located_results]
    run_mutations: list[dict[str, Any]] = []
    if side == "candidate":
        run_mutations.append(_project_candidate_version(run, plan))

    indices = {
        located.semantic_id: index
        for index, located in enumerate(located_results)
    }
    source_root_text = str(source_root.resolve(strict=True))
    serialized = json.dumps(document, ensure_ascii=False, sort_keys=True)
    if source_root_text in serialized:
        raise ProjectionError(
            f"{side} projection retained its ambient absolute source root."
        )
    audit = {
        "rawCaptureSha256": _sha256_file(raw_path),
        "resultOrdering": "semantic-id-ordinal",
        "runMutations": run_mutations,
        "results": result_audit,
    }
    return document, indices, audit


def _finding_key(side: str, index: int) -> str:
    return f"{side}:0:{index}"


def _build_labels(
    plan: CasePlan,
    baseline_indices: Mapping[str, int],
    candidate_indices: Mapping[str, int],
) -> dict[str, Any]:
    pairs: list[dict[str, str]] = []
    expected_ambiguous: list[str] = []
    expected_resolved: list[str] = []
    expected_new: list[str] = []
    for entry in sorted(plan.entries, key=lambda item: item.semantic_id):
        if entry.presence == "both" and entry.scenario != "ambiguous":
            if entry.classification is None:
                raise ProjectionError(
                    f"Pair {entry.semantic_id} lacks a classification."
                )
            pairs.append(
                {
                    "baselineKey": _finding_key(
                        "baseline", baseline_indices[entry.semantic_id]
                    ),
                    "candidateKey": _finding_key(
                        "candidate", candidate_indices[entry.semantic_id]
                    ),
                    "classification": entry.classification,
                }
            )
        elif entry.scenario == "ambiguous":
            expected_ambiguous.extend(
                (
                    _finding_key(
                        "baseline", baseline_indices[entry.semantic_id]
                    ),
                    _finding_key(
                        "candidate", candidate_indices[entry.semantic_id]
                    ),
                )
            )
        elif entry.presence == "baseline":
            expected_resolved.append(
                _finding_key("baseline", baseline_indices[entry.semantic_id])
            )
        elif entry.presence == "candidate":
            expected_new.append(
                _finding_key("candidate", candidate_indices[entry.semantic_id])
            )
        else:
            raise ProjectionError(f"Unsupported plan entry {entry.semantic_id}.")

    return {
        "schemaVersion": "1",
        "pairs": pairs,
        "expectedAmbiguous": expected_ambiguous,
        "expectedResolved": expected_resolved,
        "expectedNew": expected_new,
        "expectedInvalidInputs": [],
    }


def _stable_json_bytes(document: Any) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def project_case(case_root: Path, capture_root: Path, output_root: Path) -> None:
    """Project one producer case and derive its ground-truth labels."""

    plan_path = case_root / "producer-input" / "case-plan.json"
    plan = _parse_plan(plan_path)
    if case_root.name != plan.producer:
        raise ProjectionError(
            f"Case directory {case_root.name!r} differs from producer "
            f"{plan.producer!r}."
        )

    projected_documents: dict[str, dict[str, Any]] = {}
    indices: dict[str, Mapping[str, int]] = {}
    side_audits: dict[str, dict[str, Any]] = {}
    for side in ("baseline", "candidate"):
        projected, side_indices, side_audit = _project_capture(
            capture_root / f"{side}.raw.sarif",
            case_root / "producer-input" / side,
            side,
            plan,
        )
        projected_documents[side] = projected
        indices[side] = side_indices
        side_audits[side] = side_audit

    labels = _build_labels(
        plan,
        indices["baseline"],
        indices["candidate"],
    )
    for side in ("baseline", "candidate"):
        _write_atomic(
            output_root / f"{side}.sarif",
            _stable_json_bytes(projected_documents[side]),
        )
    _write_atomic(output_root / "labels.json", _stable_json_bytes(labels))
    projection_audit = {
        "schemaVersion": "1",
        "producer": plan.producer,
        "producerVersion": plan.producer_version,
        "projectionVersion": plan.projection_version,
        "casePlanSha256": _sha256_file(plan_path),
        "sides": side_audits,
    }
    _write_atomic(
        output_root / "producer-input" / "projection-audit.json",
        _stable_json_bytes(projection_audit),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Project one authentic holdout capture and generate labels from "
            "its source-authored case plan."
        )
    )
    parser.add_argument("--case-root", type=Path, required=True)
    parser.add_argument("--capture-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        project_case(
            parsed.case_root.resolve(strict=True),
            parsed.capture_root.resolve(strict=True),
            parsed.output_root.resolve(),
        )
    except (OSError, ProjectionError) as error:
        print(f"holdout projection failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
