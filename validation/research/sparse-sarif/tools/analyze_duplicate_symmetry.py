#!/usr/bin/env python3
"""Measure the duplicate-symmetry boundary in the sparse PMD evidence.

Feature extraction reads only SARIF observations and side-bound source snapshots.
Ground-truth labels are loaded afterwards and are used exclusively for scoring.
The tool is a research validator; it does not implement a product matcher tier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, Iterable, Mapping, Sequence, TypeAlias
from urllib.parse import unquote, urlsplit


JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)
Pair: TypeAlias = tuple[str, str, str]
TokenLine: TypeAlias = tuple[str, ...]

ANALYSIS_SCHEMA_VERSION: Final = "duplicate-symmetry-analysis/v2"
FEATURE_ALGORITHM_VERSION: Final = "comment-free-lexical-scope/v1"
SAFE_ALGORITHM_VERSION: Final = "safe-unique-continuity/v1"
FILENAME_BOUND_ALGORITHM_VERSION: Final = "trusted-filename-lexical-context/v1"
ORDER_ALGORITHM_VERSION: Final = "source-order-alignment-control/v1"
FIXED_OBSERVATION_VERSION: Final = "duplicate-symmetry-fixed-observations/v2"
MARKER_PREFIX: Final = "HOLDOUT:"
MUTATED_MARKER_PREFIX: Final = "MUTATED:"
REPARSE_POINT_ATTRIBUTE: Final = 0x400

TOKEN_PATTERN: Final = re.compile(
    r'[A-Za-z_$][A-Za-z0-9_$]*|\d+(?:\.\d+)?|"(?:\\.|[^"\\])*"|'
    r"'(?:\\.|[^'\\])*'|==|!=|<=|>=|&&|\|\||::|->|\+\+|--|[^\s]"
)
CONTROL_BLOCK_KEYWORDS: Final = frozenset(
    {"catch", "do", "else", "for", "if", "switch", "synchronized", "try", "while"}
)


@dataclass(frozen=True)
class ResourceLimits:
    """Fail-closed limits for all untrusted analysis inputs."""

    maximum_input_files: int = 256
    maximum_total_input_bytes: int = 64 * 1024 * 1024
    maximum_json_file_bytes: int = 8 * 1024 * 1024
    maximum_source_file_bytes: int = 1024 * 1024
    maximum_json_depth: int = 64
    maximum_json_nodes_per_file: int = 250_000
    maximum_total_json_nodes: int = 1_000_000
    maximum_collection_items: int = 20_000
    maximum_string_characters: int = 1024 * 1024
    maximum_integer_digits: int = 20
    maximum_results_per_side: int = 10_000
    maximum_source_lines: int = 100_000
    maximum_source_tokens_per_file: int = 200_000
    maximum_total_source_tokens: int = 2_000_000
    maximum_duplicate_group_size: int = 64


DEFAULT_LIMITS: Final = ResourceLimits()


@dataclass(frozen=True)
class DatasetSpec:
    """Location and source topology for one fixed evidence family."""

    dataset_id: str
    labels_kind: str
    case_root: str


DATASET_SPECS: Final = (
    DatasetSpec(
        "pmd-clean-a",
        "clean",
        "validation/research/sparse-sarif/cases/pmd-clean-a",
    ),
    DatasetSpec(
        "pmd-clean-b",
        "clean",
        "validation/research/sparse-sarif/cases/pmd-clean-b",
    ),
    DatasetSpec(
        "pmd-legacy",
        "legacy",
        "validation/holdout/cases/pmd",
    ),
)


FIXED_OBSERVATIONS: Final = {
    "clean": {
        "filenameBound": {
            "ambiguityEndpoints": [6, 0, 3],
            "newEndpoints": [3, 3, 0],
            "relationships": [18, 0, 1],
            "resolvedEndpoints": [3, 2, 0],
        },
        "safeUniqueness": {
            "ambiguityEndpoints": [9, 0, 0],
            "newEndpoints": [3, 0, 0],
            "relationships": [19, 0, 0],
            "resolvedEndpoints": [3, 0, 0],
        },
        "sourceOrderControl": {
            "ambiguityEndpoints": [9, 0, 0],
            "newEndpoints": [3, 0, 0],
            "relationships": [19, 0, 0],
            "resolvedEndpoints": [3, 0, 0],
        },
    },
    "legacy": {
        "filenameBound": {
            "ambiguityEndpoints": [4, 50, 0],
            "newEndpoints": [3, 0, 0],
            "relationships": [0, 0, 25],
            "resolvedEndpoints": [3, 0, 0],
        },
        "safeUniqueness": {
            "ambiguityEndpoints": [4, 50, 0],
            "newEndpoints": [3, 0, 0],
            "relationships": [0, 0, 25],
            "resolvedEndpoints": [3, 0, 0],
        },
        "sourceOrderControl": {
            "ambiguityEndpoints": [0, 0, 4],
            "newEndpoints": [3, 0, 0],
            "relationships": [25, 2, 0],
            "resolvedEndpoints": [3, 0, 0],
        },
    },
    "legacySymmetry": {
        "duplicateGroups": 6,
        "groupsWithCardinality2": 1,
        "groupsWithCardinality5": 5,
        "permutationCounts": [2, 120, 120, 120, 120, 120],
        "semanticEdgeCounts": [4, 25, 25, 25, 25, 25],
    },
    "markerMutation": {
        "filesChecked": 8,
        "invariant": True,
        "markerOccurrences": 60,
    },
}


class AnalysisError(ValueError):
    """A deterministic fail-closed validation error."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = " ".join(detail.split())


class DuplicateKeyError(ValueError):
    """Raised internally when an object repeats a JSON member name."""


@dataclass(frozen=True)
class Scope:
    """One comment-free, method-like lexical brace scope."""

    start_line: int
    end_line: int
    header: TokenLine


@dataclass(frozen=True)
class SourceModel:
    """Bounded, label-blind source features for one snapshot file."""

    relative_path: str
    token_lines: tuple[TokenLine, ...]
    scopes: tuple[Scope, ...]

    def scope_at(self, line_number: int) -> Scope:
        candidates = [
            scope
            for scope in self.scopes
            if scope.start_line <= line_number <= scope.end_line
        ]
        if not candidates:
            return Scope(1, len(self.token_lines), ())
        return min(
            candidates,
            key=lambda scope: (scope.end_line - scope.start_line, scope.start_line),
        )

    def scope_content(self, scope: Scope) -> tuple[TokenLine, ...]:
        return tuple(
            token_line
            for token_line in self.token_lines[scope.start_line - 1 : scope.end_line]
            if token_line
        )

    def feature_digest(self) -> str:
        feature_document: JsonValue = {
            "scopes": [
                {
                    "endLine": scope.end_line,
                    "header": list(scope.header),
                    "startLine": scope.start_line,
                }
                for scope in self.scopes
            ],
            "tokenLines": [list(token_line) for token_line in self.token_lines],
        }
        return hashlib.sha256(canonical_json_bytes(feature_document)).hexdigest()


@dataclass(frozen=True)
class Finding:
    """One SARIF observation enriched only with side-bound source features."""

    key: str
    side: str
    rule_id: str
    artifact_uri: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    message: str
    source_path: str
    scope_header: TokenLine
    scope_content: tuple[TokenLine, ...]
    statement: TokenLine

    @property
    def lexical_signature(self) -> tuple[str, TokenLine, TokenLine]:
        return (self.rule_id, self.scope_header, self.statement)

    @property
    def scope_signature(self) -> tuple[str, TokenLine]:
        return (self.rule_id, self.scope_header)

    @property
    def source_order(self) -> tuple[int, int, int, int, str]:
        return (
            self.start_line,
            self.start_column,
            self.end_line,
            self.end_column,
            self.key,
        )


@dataclass(frozen=True)
class DatasetFeatures:
    """Label-free observations for both sides of one dataset."""

    spec: DatasetSpec
    baseline: tuple[Finding, ...]
    candidate: tuple[Finding, ...]


@dataclass(frozen=True)
class ExpectedOutcome:
    """Ground truth loaded only after every feature and prediction exists."""

    pairs: frozenset[Pair]
    ambiguous: frozenset[str]
    new: frozenset[str]
    resolved: frozenset[str]


@dataclass(frozen=True)
class Prediction:
    """One algorithm's complete pairing and lifecycle projection."""

    pairs: frozenset[Pair]
    ambiguous: frozenset[str]
    new: frozenset[str]
    resolved: frozenset[str]


class BoundedRepositoryReader:
    """Reads a fixed repository tree with strict aggregate resource accounting."""

    def __init__(
        self,
        repository_root: Path,
        limits: ResourceLimits = DEFAULT_LIMITS,
    ) -> None:
        self.root = repository_root.resolve(strict=True)
        self.limits = limits
        self._payloads: dict[str, bytes] = {}
        self._json_documents: dict[str, JsonValue] = {}
        self.total_input_bytes = 0
        self.total_json_nodes = 0
        self.total_source_tokens = 0
        self._assert_real_path(self.root, ".")

    @property
    def input_file_count(self) -> int:
        return len(self._payloads)

    @property
    def input_paths(self) -> tuple[str, ...]:
        """Return the deterministic audit set of paths opened so far."""

        return tuple(sorted(self._payloads))

    def read_json(self, relative_path: str) -> JsonValue:
        canonical_path = self._canonical_relative_path(relative_path)
        if canonical_path in self._json_documents:
            return self._json_documents[canonical_path]
        payload = self._read_bytes(
            canonical_path,
            maximum_bytes=self.limits.maximum_json_file_bytes,
        )
        _validate_json_lexical_depth(payload, self.limits.maximum_json_depth)
        try:
            document = json.loads(
                payload,
                object_pairs_hook=_reject_duplicate_members,
                parse_constant=_reject_non_finite_number,
                parse_int=lambda value: _parse_bounded_integer(
                    value, self.limits.maximum_integer_digits
                ),
            )
        except DuplicateKeyError as error:
            raise AnalysisError(
                "JSON_DUPLICATE_KEY",
                f"{canonical_path} repeats object member {error}",
            ) from error
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) as error:
            raise AnalysisError(
                "JSON_INVALID",
                f"{canonical_path} is not bounded strict JSON: {error}",
            ) from error
        node_count = _validate_json_tree(document, self.limits, canonical_path)
        if node_count > self.limits.maximum_json_nodes_per_file:
            raise AnalysisError(
                "JSON_NODE_LIMIT",
                f"{canonical_path} exceeds {self.limits.maximum_json_nodes_per_file} JSON nodes",
            )
        self.total_json_nodes += node_count
        if self.total_json_nodes > self.limits.maximum_total_json_nodes:
            raise AnalysisError(
                "JSON_TOTAL_NODE_LIMIT",
                f"JSON inputs exceed {self.limits.maximum_total_json_nodes} total nodes",
            )
        self._json_documents[canonical_path] = document
        return document

    def read_source(self, relative_path: str) -> str:
        canonical_path = self._canonical_relative_path(relative_path)
        payload = self._read_bytes(
            canonical_path,
            maximum_bytes=self.limits.maximum_source_file_bytes,
        )
        try:
            source = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise AnalysisError(
                "SOURCE_UTF8",
                f"{canonical_path} is not valid UTF-8",
            ) from error
        if source.startswith("\ufeff"):
            raise AnalysisError("SOURCE_BOM", f"{canonical_path} starts with a UTF-8 BOM")
        if "\x00" in source:
            raise AnalysisError("SOURCE_NUL", f"{canonical_path} contains a NUL character")
        return source

    def consume_source_tokens(self, relative_path: str, token_count: int) -> None:
        if token_count > self.limits.maximum_source_tokens_per_file:
            raise AnalysisError(
                "SOURCE_TOKEN_LIMIT",
                f"{relative_path} exceeds {self.limits.maximum_source_tokens_per_file} tokens",
            )
        self.total_source_tokens += token_count
        if self.total_source_tokens > self.limits.maximum_total_source_tokens:
            raise AnalysisError(
                "SOURCE_TOTAL_TOKEN_LIMIT",
                f"source analysis exceeds {self.limits.maximum_total_source_tokens} total tokens",
            )

    def _read_bytes(self, relative_path: str, *, maximum_bytes: int) -> bytes:
        cached = self._payloads.get(relative_path)
        if cached is not None:
            if len(cached) > maximum_bytes:
                raise AnalysisError(
                    "INPUT_FILE_LIMIT",
                    f"{relative_path} exceeds its {maximum_bytes}-byte limit",
                )
            return cached
        if len(self._payloads) >= self.limits.maximum_input_files:
            raise AnalysisError(
                "INPUT_FILE_COUNT_LIMIT",
                f"analysis exceeds {self.limits.maximum_input_files} input files",
            )
        path = self.root.joinpath(*PurePosixPath(relative_path).parts)
        self._assert_contained_real_file(path, relative_path)
        try:
            declared_size = path.stat().st_size
        except OSError as error:
            raise AnalysisError("INPUT_STAT", f"cannot inspect {relative_path}") from error
        if declared_size > maximum_bytes:
            raise AnalysisError(
                "INPUT_FILE_LIMIT",
                f"{relative_path} exceeds its {maximum_bytes}-byte limit",
            )
        try:
            with path.open("rb") as stream:
                payload = stream.read(maximum_bytes + 1)
        except OSError as error:
            raise AnalysisError("INPUT_READ", f"cannot read {relative_path}") from error
        if len(payload) > maximum_bytes:
            raise AnalysisError(
                "INPUT_FILE_LIMIT",
                f"{relative_path} exceeds its {maximum_bytes}-byte limit",
            )
        if self.total_input_bytes + len(payload) > self.limits.maximum_total_input_bytes:
            raise AnalysisError(
                "INPUT_TOTAL_BYTE_LIMIT",
                f"analysis exceeds {self.limits.maximum_total_input_bytes} input bytes",
            )
        self.total_input_bytes += len(payload)
        self._payloads[relative_path] = payload
        return payload

    def _canonical_relative_path(self, relative_path: str) -> str:
        if "\\" in relative_path:
            raise AnalysisError("INPUT_PATH", "input paths must use forward slashes")
        path = PurePosixPath(relative_path)
        if path.is_absolute() or not path.parts or any(
            part in {"", ".", ".."} for part in path.parts
        ):
            raise AnalysisError("INPUT_PATH", f"invalid repository-relative path {relative_path}")
        return path.as_posix()

    def _assert_contained_real_file(self, path: Path, relative_path: str) -> None:
        current = self.root
        for component in PurePosixPath(relative_path).parts:
            current = current / component
            self._assert_real_path(current, relative_path)
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise AnalysisError("INPUT_MISSING", f"missing input {relative_path}") from error
        if not resolved.is_relative_to(self.root):
            raise AnalysisError("INPUT_ESCAPE", f"input escapes repository root: {relative_path}")
        try:
            mode = resolved.stat().st_mode
        except OSError as error:
            raise AnalysisError("INPUT_STAT", f"cannot inspect {relative_path}") from error
        if not stat.S_ISREG(mode):
            raise AnalysisError("INPUT_TYPE", f"input is not a regular file: {relative_path}")

    @staticmethod
    def _assert_real_path(path: Path, display_path: str) -> None:
        try:
            path_status = path.lstat()
        except OSError as error:
            raise AnalysisError("INPUT_MISSING", f"missing input {display_path}") from error
        file_attributes = getattr(path_status, "st_file_attributes", 0)
        if stat.S_ISLNK(path_status.st_mode) or file_attributes & REPARSE_POINT_ATTRIBUTE:
            raise AnalysisError("INPUT_LINK", f"input traverses a link: {display_path}")


class SourceFeatureExtractor:
    """Builds and caches source models without reading any label document."""

    def __init__(self, reader: BoundedRepositoryReader) -> None:
        self.reader = reader
        self._models: dict[str, SourceModel] = {}

    def model_for_path(self, relative_path: str) -> SourceModel:
        cached = self._models.get(relative_path)
        if cached is not None:
            return cached
        source = self.reader.read_source(relative_path)
        model = self.model_from_text(relative_path, source, account_tokens=True)
        self._models[relative_path] = model
        return model

    def model_from_text(
        self,
        relative_path: str,
        source: str,
        *,
        account_tokens: bool,
    ) -> SourceModel:
        line_count = source.count("\n") + 1
        if line_count > self.reader.limits.maximum_source_lines:
            raise AnalysisError(
                "SOURCE_LINE_LIMIT",
                f"{relative_path} exceeds {self.reader.limits.maximum_source_lines} lines",
            )
        stripped_source = strip_comments_preserving_lines(source)
        if stripped_source.count("\n") != source.count("\n"):
            raise AnalysisError(
                "SOURCE_LINE_INVARIANT",
                f"comment stripping changed line topology for {relative_path}",
            )
        token_lines = tuple(tokenize(line) for line in stripped_source.splitlines())
        token_count = sum(len(token_line) for token_line in token_lines)
        if account_tokens:
            self.reader.consume_source_tokens(relative_path, token_count)
        elif token_count > self.reader.limits.maximum_source_tokens_per_file:
            raise AnalysisError(
                "SOURCE_TOKEN_LIMIT",
                f"{relative_path} exceeds "
                f"{self.reader.limits.maximum_source_tokens_per_file} tokens",
            )
        scopes = discover_method_like_scopes(token_lines)
        return SourceModel(relative_path, token_lines, scopes)


# Time O(n); Space O(n), where n is the number of source characters.
def strip_comments_preserving_lines(source: str) -> str:
    """Replace Java/C-style comment characters with spaces, preserving newlines."""

    output: list[str] = []
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if current == "\n":
                output.append("\n")
                state = "code"
            else:
                output.append(" ")
            index += 1
            continue
        if state == "block-comment":
            if current == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                state = "code"
                continue
            output.append("\n" if current == "\n" else " ")
            index += 1
            continue
        if state == "string":
            output.append(current)
            if current == "\\" and following:
                output.append(following)
                index += 2
                continue
            if current == quote:
                state = "code"
            index += 1
            continue
        if current == "/" and following == "/":
            output.extend((" ", " "))
            index += 2
            state = "line-comment"
            continue
        if current == "/" and following == "*":
            output.extend((" ", " "))
            index += 2
            state = "block-comment"
            continue
        if current in {'"', "'"}:
            quote = current
            state = "string"
        output.append(current)
        index += 1
    return "".join(output)


def tokenize(line: str) -> TokenLine:
    """Return a deterministic language-neutral lexical token line."""

    return tuple(TOKEN_PATTERN.findall(line))


def _looks_like_method_header(tokens: TokenLine) -> bool:
    if "{" not in tokens or "(" not in tokens or ")" not in tokens:
        return False
    first_identifier = next(
        (
            token
            for token in tokens
            if token and (token[0].isalpha() or token[0] in "_$")
        ),
        "",
    )
    return first_identifier not in CONTROL_BLOCK_KEYWORDS


# Time O(t); Space O(s), for t tokens and s discovered lexical scopes.
def discover_method_like_scopes(token_lines: Sequence[TokenLine]) -> tuple[Scope, ...]:
    """Discover bounded brace scopes using syntax-neutral method-header evidence."""

    brace_depth = 0
    active: list[tuple[int, int, TokenLine]] = []
    completed: list[Scope] = []
    for line_number, tokens in enumerate(token_lines, start=1):
        opening_braces = tokens.count("{")
        closing_braces = tokens.count("}")
        if _looks_like_method_header(tokens):
            header = tokens[: tokens.index("{")]
            active.append((brace_depth + 1, line_number, header))
        brace_depth += opening_braces - closing_braces
        while active and brace_depth < active[-1][0]:
            _, start_line, header = active.pop()
            completed.append(Scope(start_line, line_number, header))
    final_line = len(token_lines)
    while active:
        _, start_line, header = active.pop()
        completed.append(Scope(start_line, final_line, header))
    return tuple(
        sorted(
            completed,
            key=lambda scope: (scope.start_line, scope.end_line, scope.header),
        )
    )


def extract_all_features(
    reader: BoundedRepositoryReader,
    source_extractor: SourceFeatureExtractor,
) -> tuple[DatasetFeatures, ...]:
    """Extract every observation before any label path is opened."""

    return tuple(
        extract_dataset_features(reader, source_extractor, spec)
        for spec in DATASET_SPECS
    )


def extract_dataset_features(
    reader: BoundedRepositoryReader,
    source_extractor: SourceFeatureExtractor,
    spec: DatasetSpec,
) -> DatasetFeatures:
    """Extract SARIF/source evidence for a dataset without consulting labels."""

    baseline = _extract_side(reader, source_extractor, spec, "baseline")
    candidate = _extract_side(reader, source_extractor, spec, "candidate")
    return DatasetFeatures(spec, baseline, candidate)


def _extract_side(
    reader: BoundedRepositoryReader,
    source_extractor: SourceFeatureExtractor,
    spec: DatasetSpec,
    side: str,
) -> tuple[Finding, ...]:
    sarif_path = f"{spec.case_root}/{side}.sarif"
    document = _require_mapping(reader.read_json(sarif_path), sarif_path)
    runs = _require_list(document.get("runs"), f"{sarif_path}#/runs")
    findings: list[Finding] = []
    for run_index, run_value in enumerate(runs):
        run = _require_mapping(run_value, f"{sarif_path}#/runs/{run_index}")
        results = _require_list(
            run.get("results"),
            f"{sarif_path}#/runs/{run_index}/results",
        )
        if len(findings) + len(results) > reader.limits.maximum_results_per_side:
            raise AnalysisError(
                "SARIF_RESULT_LIMIT",
                f"{spec.dataset_id} {side} exceeds "
                f"{reader.limits.maximum_results_per_side} results",
            )
        for result_index, result_value in enumerate(results):
            pointer = f"{sarif_path}#/runs/{run_index}/results/{result_index}"
            result = _require_mapping(result_value, pointer)
            rule_id = _require_string(result.get("ruleId"), f"{pointer}/ruleId")
            message = _require_mapping(result.get("message"), f"{pointer}/message")
            message_text = _require_string(message.get("text"), f"{pointer}/message/text")
            locations = _require_list(result.get("locations"), f"{pointer}/locations")
            if not locations:
                raise AnalysisError("SARIF_LOCATION", f"{pointer} has no primary location")
            location = _require_mapping(locations[0], f"{pointer}/locations/0")
            physical = _require_mapping(
                location.get("physicalLocation"),
                f"{pointer}/locations/0/physicalLocation",
            )
            artifact = _require_mapping(
                physical.get("artifactLocation"),
                f"{pointer}/locations/0/physicalLocation/artifactLocation",
            )
            artifact_uri = canonical_artifact_uri(
                _require_string(artifact.get("uri"), f"{pointer}/artifactUri")
            )
            region = _require_mapping(physical.get("region"), f"{pointer}/region")
            start_line = _require_positive_integer(region.get("startLine"), f"{pointer}/startLine")
            start_column = _optional_positive_integer(region.get("startColumn"), 1, pointer)
            end_line = _optional_positive_integer(region.get("endLine"), start_line, pointer)
            end_column = _optional_positive_integer(
                region.get("endColumn"), start_column, pointer
            )
            source_path = source_path_for(spec, side, artifact_uri)
            source_model = source_extractor.model_for_path(source_path)
            if start_line > len(source_model.token_lines):
                raise AnalysisError(
                    "SOURCE_REGION",
                    f"{pointer} line {start_line} is outside {source_path}",
                )
            statement = source_model.token_lines[start_line - 1]
            if not statement:
                raise AnalysisError(
                    "SOURCE_STATEMENT",
                    f"{pointer} selects an empty comment-free source line",
                )
            scope = source_model.scope_at(start_line)
            findings.append(
                Finding(
                    key=f"{side}:{run_index}:{result_index}",
                    side=side,
                    rule_id=rule_id,
                    artifact_uri=artifact_uri,
                    start_line=start_line,
                    start_column=start_column,
                    end_line=end_line,
                    end_column=end_column,
                    message=message_text,
                    source_path=source_path,
                    scope_header=scope.header,
                    scope_content=source_model.scope_content(scope),
                    statement=statement,
                )
            )
    return tuple(findings)


def canonical_artifact_uri(uri: str) -> str:
    """Normalize a PMD relative/file URI to its source-root-relative spelling."""

    parsed = urlsplit(uri)
    if parsed.scheme and parsed.scheme.lower() != "file":
        raise AnalysisError("SARIF_URI", "only relative and file artifact URIs are admitted")
    path = unquote(parsed.path) if parsed.scheme else uri
    normalized = path.replace("\\", "/")
    source_marker_index = normalized.lower().rfind("/src/")
    if source_marker_index >= 0:
        normalized = normalized[source_marker_index + 1 :]
    normalized = normalized.lstrip("/")
    path_parts = PurePosixPath(normalized).parts
    if not path_parts or any(part in {"", ".", ".."} for part in path_parts):
        raise AnalysisError("SARIF_URI", "artifact URI is not a contained relative path")
    return PurePosixPath(*path_parts).as_posix()


def source_path_for(spec: DatasetSpec, side: str, artifact_uri: str) -> str:
    """Bind an observation to only its own immutable source snapshot root."""

    if spec.labels_kind == "legacy":
        return f"{spec.case_root}/producer-input/{side}/{artifact_uri}"
    return f"{spec.case_root}/{side}/source/{artifact_uri}"


def load_all_expectations(
    reader: BoundedRepositoryReader,
    feature_sets: Sequence[DatasetFeatures],
) -> dict[str, ExpectedOutcome]:
    """Load labels only after label-blind prediction inputs have been frozen."""

    expectations: dict[str, ExpectedOutcome] = {}
    for features in feature_sets:
        labels_path = f"{features.spec.case_root}/labels.json"
        labels = _require_mapping(reader.read_json(labels_path), labels_path)
        if features.spec.labels_kind == "legacy":
            outcome = _load_legacy_expectation(features, labels, labels_path)
        else:
            outcome = _load_clean_expectation(features, labels, labels_path)
        expectations[features.spec.dataset_id] = outcome
    return expectations


def _load_legacy_expectation(
    features: DatasetFeatures,
    labels: Mapping[str, JsonValue],
    labels_path: str,
) -> ExpectedOutcome:
    pairs = frozenset(
        (
            _require_string(entry.get("baselineKey"), f"{labels_path}#/pairs/baselineKey"),
            _require_string(entry.get("candidateKey"), f"{labels_path}#/pairs/candidateKey"),
            _require_string(entry.get("classification"), f"{labels_path}#/pairs/classification"),
        )
        for entry in (
            _require_mapping(value, f"{labels_path}#/pairs")
            for value in _require_list(labels.get("pairs"), f"{labels_path}#/pairs")
        )
    )
    ambiguous = frozenset(
        _require_string(value, f"{labels_path}#/expectedAmbiguous")
        for value in _require_list(
            labels.get("expectedAmbiguous"),
            f"{labels_path}#/expectedAmbiguous",
        )
    )
    new = frozenset(
        _require_string(value, f"{labels_path}#/expectedNew")
        for value in _require_list(labels.get("expectedNew"), f"{labels_path}#/expectedNew")
    )
    resolved = frozenset(
        _require_string(value, f"{labels_path}#/expectedResolved")
        for value in _require_list(
            labels.get("expectedResolved"),
            f"{labels_path}#/expectedResolved",
        )
    )
    _validate_expected_keys(features, pairs, ambiguous, new, resolved, labels_path)
    return ExpectedOutcome(pairs, ambiguous, new, resolved)


def _load_clean_expectation(
    features: DatasetFeatures,
    labels: Mapping[str, JsonValue],
    labels_path: str,
) -> ExpectedOutcome:
    pairs: set[Pair] = set()
    for value in _require_list(labels.get("relationships"), f"{labels_path}#/relationships"):
        relationship = _require_mapping(value, f"{labels_path}#/relationships")
        pairs.add(
            (
                _selector_key(features.baseline, relationship.get("baseline"), labels_path),
                _selector_key(features.candidate, relationship.get("candidate"), labels_path),
                _require_string(
                    relationship.get("expectedClassification"),
                    f"{labels_path}#/relationships/expectedClassification",
                ),
            )
        )
    ambiguous: set[str] = set()
    for value in _require_list(labels.get("ambiguities"), f"{labels_path}#/ambiguities"):
        group = _require_mapping(value, f"{labels_path}#/ambiguities")
        for side_name, findings in (
            ("baseline", features.baseline),
            ("candidate", features.candidate),
        ):
            for selector in _require_list(
                group.get(side_name),
                f"{labels_path}#/ambiguities/{side_name}",
            ):
                ambiguous.add(_selector_key(findings, selector, labels_path))
    new = frozenset(
        _selector_key(
            features.candidate,
            _require_mapping(value, f"{labels_path}#/new").get("candidate"),
            labels_path,
        )
        for value in _require_list(labels.get("new"), f"{labels_path}#/new")
    )
    resolved = frozenset(
        _selector_key(
            features.baseline,
            _require_mapping(value, f"{labels_path}#/resolved").get("baseline"),
            labels_path,
        )
        for value in _require_list(labels.get("resolved"), f"{labels_path}#/resolved")
    )
    outcome = ExpectedOutcome(frozenset(pairs), frozenset(ambiguous), new, resolved)
    _validate_expected_keys(
        features,
        outcome.pairs,
        outcome.ambiguous,
        outcome.new,
        outcome.resolved,
        labels_path,
    )
    return outcome


def _selector_key(
    findings: Sequence[Finding],
    selector_value: JsonValue,
    labels_path: str,
) -> str:
    selector = _require_mapping(selector_value, f"{labels_path}#/selector")
    region = _require_mapping(selector.get("region"), f"{labels_path}#/selector/region")
    artifact_uri = canonical_artifact_uri(
        _require_string(selector.get("artifactUri"), f"{labels_path}#/selector/artifactUri")
    )
    start_line = _require_positive_integer(region.get("startLine"), labels_path)
    start_column = _optional_positive_integer(region.get("startColumn"), 1, labels_path)
    end_line = _optional_positive_integer(region.get("endLine"), start_line, labels_path)
    end_column = _optional_positive_integer(region.get("endColumn"), start_column, labels_path)
    rule_id = _require_string(selector.get("ruleId"), f"{labels_path}#/selector/ruleId")
    message = _require_string(selector.get("message"), f"{labels_path}#/selector/message")
    matches = [
        finding.key
        for finding in findings
        if (
            finding.rule_id == rule_id
            and finding.artifact_uri == artifact_uri
            and finding.start_line == start_line
            and finding.start_column == start_column
            and finding.end_line == end_line
            and finding.end_column == end_column
            and finding.message == message
        )
    ]
    if len(matches) != 1:
        raise AnalysisError(
            "LABEL_SELECTOR",
            f"{labels_path} selector resolved to {len(matches)} observations",
        )
    return matches[0]


def _validate_expected_keys(
    features: DatasetFeatures,
    pairs: Iterable[Pair],
    ambiguous: Iterable[str],
    new: Iterable[str],
    resolved: Iterable[str],
    labels_path: str,
) -> None:
    baseline_keys = {finding.key for finding in features.baseline}
    candidate_keys = {finding.key for finding in features.candidate}
    for baseline_key, candidate_key, _ in pairs:
        if baseline_key not in baseline_keys or candidate_key not in candidate_keys:
            raise AnalysisError("LABEL_KEY", f"{labels_path} references an unknown pair endpoint")
    if any(
        key not in baseline_keys | candidate_keys
        for key in ambiguous
    ) or any(key not in candidate_keys for key in new) or any(
        key not in baseline_keys for key in resolved
    ):
        raise AnalysisError("LABEL_KEY", f"{labels_path} references an unknown endpoint")


# Time O(B + C) expected; Space O(B + C), for B/C side findings.
def predict_safe_uniqueness(features: DatasetFeatures) -> Prediction:
    """Accept only unique semantic observations; refuse every equal rival."""

    pairs: list[tuple[Finding, Finding]] = []
    ambiguous: set[str] = set()
    handled_baseline: set[str] = set()
    handled_candidate: set[str] = set()

    def consume_stage(*, include_path: bool) -> None:
        baseline_groups: dict[object, list[Finding]] = defaultdict(list)
        candidate_groups: dict[object, list[Finding]] = defaultdict(list)
        for finding in features.baseline:
            if finding.key not in handled_baseline:
                key: object = (
                    (finding.artifact_uri, finding.lexical_signature)
                    if include_path
                    else finding.lexical_signature
                )
                baseline_groups[key].append(finding)
        for finding in features.candidate:
            if finding.key not in handled_candidate:
                key = (
                    (finding.artifact_uri, finding.lexical_signature)
                    if include_path
                    else finding.lexical_signature
                )
                candidate_groups[key].append(finding)
        for key in sorted(set(baseline_groups) & set(candidate_groups), key=repr):
            baseline_group = baseline_groups[key]
            candidate_group = candidate_groups[key]
            if len(baseline_group) == len(candidate_group) == 1:
                pairs.append((baseline_group[0], candidate_group[0]))
            else:
                ambiguous.update(
                    finding.key for finding in baseline_group + candidate_group
                )
            handled_baseline.update(finding.key for finding in baseline_group)
            handled_candidate.update(finding.key for finding in candidate_group)

    consume_stage(include_path=True)
    consume_stage(include_path=False)
    _refuse_same_path_statement_rivals(
        features,
        handled_baseline,
        handled_candidate,
        ambiguous,
    )
    return _complete_prediction(features, pairs, ambiguous)


# Time O(B + C) expected; Space O(B + C), for B/C side findings.
def predict_filename_bound_uniqueness(features: DatasetFeatures) -> Prediction:
    """Accept only unique filename-and-lexical atoms and refuse equal rivals."""

    baseline_groups: dict[object, list[Finding]] = defaultdict(list)
    candidate_groups: dict[object, list[Finding]] = defaultdict(list)
    for finding in features.baseline:
        baseline_groups[
            (PurePosixPath(finding.artifact_uri).name, finding.lexical_signature)
        ].append(finding)
    for finding in features.candidate:
        candidate_groups[
            (PurePosixPath(finding.artifact_uri).name, finding.lexical_signature)
        ].append(finding)

    pairs: list[tuple[Finding, Finding]] = []
    ambiguous: set[str] = set()
    for key in sorted(set(baseline_groups) & set(candidate_groups), key=repr):
        baseline_group = baseline_groups[key]
        candidate_group = candidate_groups[key]
        if len(baseline_group) == len(candidate_group) == 1:
            pairs.append((baseline_group[0], candidate_group[0]))
        else:
            ambiguous.update(
                finding.key for finding in baseline_group + candidate_group
            )
    return _complete_prediction(features, pairs, ambiguous)


# Time O(B log B + C log C); Space O(B + C), for B/C side findings.
def predict_source_order_control(features: DatasetFeatures) -> Prediction:
    """Pair duplicate observations by source order as an intentionally unsafe control."""

    pairs: list[tuple[Finding, Finding]] = []
    ambiguous: set[str] = set()
    handled_baseline: set[str] = set()
    handled_candidate: set[str] = set()

    def consume_stage(*, include_path: bool) -> None:
        baseline_scopes: dict[object, list[Finding]] = defaultdict(list)
        candidate_scopes: dict[object, list[Finding]] = defaultdict(list)
        for finding in features.baseline:
            if finding.key not in handled_baseline:
                key: object = (
                    (finding.artifact_uri, finding.scope_signature)
                    if include_path
                    else finding.scope_signature
                )
                baseline_scopes[key].append(finding)
        for finding in features.candidate:
            if finding.key not in handled_candidate:
                key = (
                    (finding.artifact_uri, finding.scope_signature)
                    if include_path
                    else finding.scope_signature
                )
                candidate_scopes[key].append(finding)
        for scope_key in sorted(
            set(baseline_scopes) & set(candidate_scopes), key=repr
        ):
            baseline_statements = _group_by_statement(baseline_scopes[scope_key])
            candidate_statements = _group_by_statement(candidate_scopes[scope_key])
            for statement in sorted(
                set(baseline_statements) & set(candidate_statements)
            ):
                baseline_group = sorted(
                    baseline_statements[statement], key=lambda finding: finding.source_order
                )
                candidate_group = sorted(
                    candidate_statements[statement], key=lambda finding: finding.source_order
                )
                if len(baseline_group) == len(candidate_group):
                    pairs.extend(zip(baseline_group, candidate_group, strict=True))
                else:
                    ambiguous.update(
                        finding.key for finding in baseline_group + candidate_group
                    )
                handled_baseline.update(finding.key for finding in baseline_group)
                handled_candidate.update(finding.key for finding in candidate_group)

    consume_stage(include_path=True)
    consume_stage(include_path=False)
    _refuse_same_path_statement_rivals(
        features,
        handled_baseline,
        handled_candidate,
        ambiguous,
    )
    return _complete_prediction(features, pairs, ambiguous)


def _group_by_statement(findings: Iterable[Finding]) -> dict[TokenLine, list[Finding]]:
    groups: dict[TokenLine, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.statement].append(finding)
    return groups


def _refuse_same_path_statement_rivals(
    features: DatasetFeatures,
    handled_baseline: set[str],
    handled_candidate: set[str],
    ambiguous: set[str],
) -> None:
    baseline_groups: dict[object, list[Finding]] = defaultdict(list)
    candidate_groups: dict[object, list[Finding]] = defaultdict(list)
    for finding in features.baseline:
        if finding.key not in handled_baseline:
            baseline_groups[
                (finding.rule_id, finding.artifact_uri, finding.statement)
            ].append(finding)
    for finding in features.candidate:
        if finding.key not in handled_candidate:
            candidate_groups[
                (finding.rule_id, finding.artifact_uri, finding.statement)
            ].append(finding)
    for key in set(baseline_groups) & set(candidate_groups):
        ambiguous.update(
            finding.key for finding in baseline_groups[key] + candidate_groups[key]
        )


def _complete_prediction(
    features: DatasetFeatures,
    finding_pairs: Iterable[tuple[Finding, Finding]],
    ambiguous: Iterable[str],
) -> Prediction:
    pair_set = frozenset(
        (
            baseline.key,
            candidate.key,
            classify_pair(baseline, candidate),
        )
        for baseline, candidate in finding_pairs
    )
    ambiguous_set = frozenset(ambiguous)
    paired_baseline = {baseline_key for baseline_key, _, _ in pair_set}
    paired_candidate = {candidate_key for _, candidate_key, _ in pair_set}
    resolved = frozenset(
        finding.key
        for finding in features.baseline
        if finding.key not in paired_baseline and finding.key not in ambiguous_set
    )
    new = frozenset(
        finding.key
        for finding in features.candidate
        if finding.key not in paired_candidate and finding.key not in ambiguous_set
    )
    return Prediction(pair_set, ambiguous_set, new, resolved)


def classify_pair(baseline: Finding, candidate: Finding) -> str:
    """Apply the repository's observable unchanged/modified/moved taxonomy."""

    same_location = (
        baseline.artifact_uri == candidate.artifact_uri
        and baseline.start_line == candidate.start_line
        and baseline.start_column == candidate.start_column
        and baseline.end_line == candidate.end_line
        and baseline.end_column == candidate.end_column
    )
    if same_location and baseline.message == candidate.message:
        return "unchanged"
    if same_location:
        return "modified"
    return "moved"


def score_prediction(prediction: Prediction, expected: ExpectedOutcome) -> dict[str, JsonValue]:
    """Score predictions only after label-blind extraction and matching finish."""

    return {
        "ambiguityEndpoints": _score_set(prediction.ambiguous, expected.ambiguous),
        "newEndpoints": _score_set(prediction.new, expected.new),
        "relationships": _score_set(prediction.pairs, expected.pairs),
        "resolvedEndpoints": _score_set(prediction.resolved, expected.resolved),
    }


def _score_set(predicted: frozenset[object], expected: frozenset[object]) -> dict[str, JsonValue]:
    true_positives = len(predicted & expected)
    false_positives = len(predicted - expected)
    false_negatives = len(expected - predicted)
    accepted = true_positives + false_positives
    labelled = true_positives + false_negatives
    return {
        "accepted": accepted,
        "falseNegatives": false_negatives,
        "falsePositives": false_positives,
        "labelled": labelled,
        "precision": None if accepted == 0 else round(true_positives / accepted, 6),
        "recall": None if labelled == 0 else round(true_positives / labelled, 6),
        "truePositives": true_positives,
    }


def aggregate_scores(scores: Iterable[Mapping[str, JsonValue]]) -> dict[str, JsonValue]:
    """Aggregate exact integer confusion counts, then derive decimal displays."""

    score_list = list(scores)
    aggregate: dict[str, JsonValue] = {}
    for category in (
        "ambiguityEndpoints",
        "newEndpoints",
        "relationships",
        "resolvedEndpoints",
    ):
        true_positives = sum(
            _require_integer(_require_mapping(score[category], category)["truePositives"], category)
            for score in score_list
        )
        false_positives = sum(
            _require_integer(
                _require_mapping(score[category], category)["falsePositives"],
                category,
            )
            for score in score_list
        )
        false_negatives = sum(
            _require_integer(
                _require_mapping(score[category], category)["falseNegatives"],
                category,
            )
            for score in score_list
        )
        accepted = true_positives + false_positives
        labelled = true_positives + false_negatives
        aggregate[category] = {
            "accepted": accepted,
            "falseNegatives": false_negatives,
            "falsePositives": false_positives,
            "labelled": labelled,
            "precision": None if accepted == 0 else round(true_positives / accepted, 6),
            "recall": None if labelled == 0 else round(true_positives / labelled, 6),
            "truePositives": true_positives,
        }
    return aggregate


def discover_symmetry_groups(
    features: DatasetFeatures,
    expected: ExpectedOutcome,
    maximum_group_size: int,
) -> list[dict[str, JsonValue]]:
    """Describe equal-weight duplicate components without choosing an assignment."""

    handled_baseline: set[str] = set()
    handled_candidate: set[str] = set()
    groups: list[tuple[list[Finding], list[Finding]]] = []

    def discover_stage(*, include_path: bool) -> None:
        baseline_groups: dict[object, list[Finding]] = defaultdict(list)
        candidate_groups: dict[object, list[Finding]] = defaultdict(list)
        for finding in features.baseline:
            if finding.key not in handled_baseline:
                key: object = (
                    (finding.artifact_uri, finding.lexical_signature)
                    if include_path
                    else finding.lexical_signature
                )
                baseline_groups[key].append(finding)
        for finding in features.candidate:
            if finding.key not in handled_candidate:
                key = (
                    (finding.artifact_uri, finding.lexical_signature)
                    if include_path
                    else finding.lexical_signature
                )
                candidate_groups[key].append(finding)
        for key in sorted(set(baseline_groups) & set(candidate_groups), key=repr):
            baseline_group = baseline_groups[key]
            candidate_group = candidate_groups[key]
            if len(baseline_group) == len(candidate_group) and len(baseline_group) > 1:
                groups.append((baseline_group, candidate_group))
            handled_baseline.update(finding.key for finding in baseline_group)
            handled_candidate.update(finding.key for finding in candidate_group)

    discover_stage(include_path=True)
    discover_stage(include_path=False)
    documents: list[dict[str, JsonValue]] = []
    for baseline_group, candidate_group in groups:
        cardinality = len(baseline_group)
        if cardinality > maximum_group_size:
            raise AnalysisError(
                "SYMMETRY_GROUP_LIMIT",
                f"duplicate group exceeds {maximum_group_size} findings per side",
            )
        baseline_keys = {finding.key for finding in baseline_group}
        candidate_keys = {finding.key for finding in candidate_group}
        labelled_relationships = sum(
            1
            for baseline_key, candidate_key, _ in expected.pairs
            if baseline_key in baseline_keys and candidate_key in candidate_keys
        )
        labelled_ambiguity_endpoints = len(
            expected.ambiguous & (baseline_keys | candidate_keys)
        )
        group_identity: JsonValue = {
            "baselineArtifacts": sorted(
                {finding.artifact_uri for finding in baseline_group}
            ),
            "candidateArtifacts": sorted(
                {finding.artifact_uri for finding in candidate_group}
            ),
            "scopeHeader": list(baseline_group[0].scope_header),
            "statement": list(baseline_group[0].statement),
        }
        group_digest = hashlib.sha256(canonical_json_bytes(group_identity)).hexdigest()[:16]
        scope_contents = {
            finding.scope_content for finding in baseline_group + candidate_group
        }
        documents.append(
            {
                "baselineArtifacts": sorted(
                    {finding.artifact_uri for finding in baseline_group}
                ),
                "baselineCoordinates": [
                    [finding.start_line, finding.start_column]
                    for finding in sorted(
                        baseline_group, key=lambda finding: finding.source_order
                    )
                ],
                "baselineCount": cardinality,
                "candidateArtifacts": sorted(
                    {finding.artifact_uri for finding in candidate_group}
                ),
                "candidateCoordinates": [
                    [finding.start_line, finding.start_column]
                    for finding in sorted(
                        candidate_group, key=lambda finding: finding.source_order
                    )
                ],
                "candidateCount": cardinality,
                "commentFreeScopeIdentity": len(scope_contents) == 1,
                "completeSemanticEdgeCount": cardinality * cardinality,
                "groupId": f"symmetry-{group_digest}",
                "labelledAmbiguityEndpoints": labelled_ambiguity_endpoints,
                "labelledRelationships": labelled_relationships,
                "maximumCardinality": cardinality,
                "maximumCardinalityAssignmentCount": math.factorial(cardinality),
                "oracleOutcome": (
                    "refuse"
                    if labelled_ambiguity_endpoints == cardinality * 2
                    else "pair"
                    if labelled_relationships == cardinality
                    else "mixed"
                ),
                "scopeHeader": list(baseline_group[0].scope_header),
                "statementTokens": list(baseline_group[0].statement),
            }
        )
    return sorted(documents, key=lambda document: _require_string(document["groupId"], "groupId"))


def marker_mutation_report(
    reader: BoundedRepositoryReader,
    source_extractor: SourceFeatureExtractor,
    legacy_features: DatasetFeatures,
) -> dict[str, JsonValue]:
    """Prove that changing marker text inside comments cannot change features."""

    source_paths = sorted(
        {
            finding.source_path
            for finding in legacy_features.baseline + legacy_features.candidate
        }
    )
    files: list[dict[str, JsonValue]] = []
    total_markers = 0
    invariant = True
    for source_path in source_paths:
        source = reader.read_source(source_path)
        marker_count = source.count(MARKER_PREFIX)
        total_markers += marker_count
        original_model = source_extractor.model_for_path(source_path)
        mutated_source = source.replace(MARKER_PREFIX, MUTATED_MARKER_PREFIX)
        mutated_model = source_extractor.model_from_text(
            source_path,
            mutated_source,
            account_tokens=True,
        )
        original_digest = original_model.feature_digest()
        mutated_digest = mutated_model.feature_digest()
        file_invariant = original_digest == mutated_digest
        invariant = invariant and file_invariant
        files.append(
            {
                "featureSha256": original_digest,
                "invariant": file_invariant,
                "markerOccurrences": marker_count,
                "mutatedFeatureSha256": mutated_digest,
                "path": source_path,
            }
        )
    return {
        "files": files,
        "filesChecked": len(files),
        "invariant": invariant,
        "markerOccurrences": total_markers,
        "mutation": f"{MARKER_PREFIX}->{MUTATED_MARKER_PREFIX}",
    }


def analyze_repository(
    repository_root: Path,
    limits: ResourceLimits = DEFAULT_LIMITS,
) -> dict[str, JsonValue]:
    """Run extraction, blind prediction, label scoring, and fixed verification."""

    reader = BoundedRepositoryReader(repository_root, limits)
    source_extractor = SourceFeatureExtractor(reader)

    # The ordering is a scientific boundary: no label document is opened until
    # every feature and both competing predictions have already been computed.
    feature_sets = extract_all_features(reader, source_extractor)
    predictions = {
        features.spec.dataset_id: {
            "filenameBound": predict_filename_bound_uniqueness(features),
            "safeUniqueness": predict_safe_uniqueness(features),
            "sourceOrderControl": predict_source_order_control(features),
        }
        for features in feature_sets
    }
    expectations = load_all_expectations(reader, feature_sets)

    dataset_reports: dict[str, JsonValue] = {}
    scores_by_dataset: dict[str, dict[str, dict[str, JsonValue]]] = {}
    symmetry_by_dataset: dict[str, list[dict[str, JsonValue]]] = {}
    for features in feature_sets:
        dataset_id = features.spec.dataset_id
        expected = expectations[dataset_id]
        algorithm_scores = {
            algorithm: score_prediction(prediction, expected)
            for algorithm, prediction in predictions[dataset_id].items()
        }
        scores_by_dataset[dataset_id] = algorithm_scores
        symmetry_groups = discover_symmetry_groups(
            features,
            expected,
            limits.maximum_duplicate_group_size,
        )
        symmetry_by_dataset[dataset_id] = symmetry_groups
        dataset_reports[dataset_id] = {
            "baselineFindings": len(features.baseline),
            "candidateFindings": len(features.candidate),
            "scores": algorithm_scores,
            "symmetryGroups": symmetry_groups,
        }

    clean_ids = ("pmd-clean-a", "pmd-clean-b")
    aggregate_scores_by_scope: dict[str, JsonValue] = {
        "clean": {
            algorithm: aggregate_scores(
                scores_by_dataset[dataset_id][algorithm] for dataset_id in clean_ids
            )
            for algorithm in (
                "filenameBound",
                "safeUniqueness",
                "sourceOrderControl",
            )
        },
        "legacy": {
            algorithm: scores_by_dataset["pmd-legacy"][algorithm]
            for algorithm in (
                "filenameBound",
                "safeUniqueness",
                "sourceOrderControl",
            )
        },
    }
    legacy_features = next(
        features
        for features in feature_sets
        if features.spec.dataset_id == "pmd-legacy"
    )
    marker_report = marker_mutation_report(reader, source_extractor, legacy_features)
    report: dict[str, JsonValue] = {
        "algorithms": {
            "featureExtraction": {
                "comments": "stripped-with-line-preservation",
                "labelBlind": True,
                "version": FEATURE_ALGORITHM_VERSION,
            },
            "filenameBound": {
                "duplicatePolicy": "refuse-equal-rivals",
                "fileIdentity": "ordinal-final-path-segment",
                "productContract": True,
                "version": FILENAME_BOUND_ALGORITHM_VERSION,
            },
            "safeUniqueness": {
                "duplicatePolicy": "refuse-equal-rivals",
                "version": SAFE_ALGORITHM_VERSION,
            },
            "sourceOrderControl": {
                "duplicatePolicy": "pair-by-source-order",
                "scientificControlOnly": True,
                "version": ORDER_ALGORITHM_VERSION,
            },
        },
        "datasets": dataset_reports,
        "fixedObservationVerification": {
            "contract": FIXED_OBSERVATION_VERSION,
            "status": "pending",
        },
        "markerMutationInvariance": marker_report,
        "resourceLimits": _resource_limit_document(limits),
        "resourceUsage": {
            "inputBytes": reader.total_input_bytes,
            "inputFiles": reader.input_file_count,
            "jsonNodes": reader.total_json_nodes,
            "sourceTokens": reader.total_source_tokens,
        },
        "schemaVersion": ANALYSIS_SCHEMA_VERSION,
        "scores": aggregate_scores_by_scope,
        "symmetryBoundary": {
            "legacyGroups": symmetry_by_dataset["pmd-legacy"],
            "orderIsSemanticEvidence": False,
            "safeRule": "equal semantic assignments remain ambiguous",
        },
    }
    verify_fixed_observations(report)
    verification = _require_mapping(
        report["fixedObservationVerification"],
        "fixedObservationVerification",
    )
    verification["status"] = "passed"
    return report


def verify_fixed_observations(report: Mapping[str, JsonValue]) -> None:
    """Fail closed if any frozen metric or symmetry count changes."""

    observed = fixed_observation_projection(report)
    if observed != FIXED_OBSERVATIONS:
        expected_digest = hashlib.sha256(canonical_json_bytes(FIXED_OBSERVATIONS)).hexdigest()
        observed_digest = hashlib.sha256(canonical_json_bytes(observed)).hexdigest()
        raise AnalysisError(
            "FIXED_OBSERVATION_MISMATCH",
            f"expected sha256:{expected_digest}, observed sha256:{observed_digest}",
        )


def fixed_observation_projection(report: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Project only the exact observations that constitute the boundary."""

    scores = _require_mapping(report.get("scores"), "scores")
    projection: dict[str, JsonValue] = {}
    for scope_name in ("clean", "legacy"):
        scope_scores = _require_mapping(scores.get(scope_name), f"scores/{scope_name}")
        algorithm_projection: dict[str, JsonValue] = {}
        for algorithm in (
            "filenameBound",
            "safeUniqueness",
            "sourceOrderControl",
        ):
            score = _require_mapping(scope_scores.get(algorithm), algorithm)
            algorithm_projection[algorithm] = {
                category: _metric_triplet(
                    _require_mapping(score.get(category), category)
                )
                for category in (
                    "ambiguityEndpoints",
                    "newEndpoints",
                    "relationships",
                    "resolvedEndpoints",
                )
            }
        projection[scope_name] = algorithm_projection

    symmetry_boundary = _require_mapping(
        report.get("symmetryBoundary"), "symmetryBoundary"
    )
    legacy_groups = [
        _require_mapping(value, "symmetryBoundary/legacyGroups")
        for value in _require_list(
            symmetry_boundary.get("legacyGroups"),
            "symmetryBoundary/legacyGroups",
        )
    ]
    cardinalities = [
        _require_integer(group.get("baselineCount"), "baselineCount")
        for group in legacy_groups
    ]
    projection["legacySymmetry"] = {
        "duplicateGroups": len(legacy_groups),
        "groupsWithCardinality2": cardinalities.count(2),
        "groupsWithCardinality5": cardinalities.count(5),
        "permutationCounts": sorted(
            _require_integer(
                group.get("maximumCardinalityAssignmentCount"),
                "maximumCardinalityAssignmentCount",
            )
            for group in legacy_groups
        ),
        "semanticEdgeCounts": sorted(
            _require_integer(
                group.get("completeSemanticEdgeCount"),
                "completeSemanticEdgeCount",
            )
            for group in legacy_groups
        ),
    }
    marker = _require_mapping(
        report.get("markerMutationInvariance"),
        "markerMutationInvariance",
    )
    projection["markerMutation"] = {
        "filesChecked": _require_integer(marker.get("filesChecked"), "filesChecked"),
        "invariant": _require_boolean(marker.get("invariant"), "invariant"),
        "markerOccurrences": _require_integer(
            marker.get("markerOccurrences"), "markerOccurrences"
        ),
    }
    return projection


def _metric_triplet(metric: Mapping[str, JsonValue]) -> list[JsonValue]:
    return [
        _require_integer(metric.get("truePositives"), "truePositives"),
        _require_integer(metric.get("falsePositives"), "falsePositives"),
        _require_integer(metric.get("falseNegatives"), "falseNegatives"),
    ]


def _resource_limit_document(limits: ResourceLimits) -> dict[str, JsonValue]:
    return {
        "maximumCollectionItems": limits.maximum_collection_items,
        "maximumDuplicateGroupSize": limits.maximum_duplicate_group_size,
        "maximumInputFiles": limits.maximum_input_files,
        "maximumJsonDepth": limits.maximum_json_depth,
        "maximumJsonFileBytes": limits.maximum_json_file_bytes,
        "maximumJsonNodesPerFile": limits.maximum_json_nodes_per_file,
        "maximumResultsPerSide": limits.maximum_results_per_side,
        "maximumSourceFileBytes": limits.maximum_source_file_bytes,
        "maximumSourceLines": limits.maximum_source_lines,
        "maximumSourceTokensPerFile": limits.maximum_source_tokens_per_file,
        "maximumStringCharacters": limits.maximum_string_characters,
        "maximumTotalInputBytes": limits.maximum_total_input_bytes,
        "maximumTotalJsonNodes": limits.maximum_total_json_nodes,
        "maximumTotalSourceTokens": limits.maximum_total_source_tokens,
    }


def canonical_json_bytes(value: JsonValue | Mapping[str, object]) -> bytes:
    """Serialize canonical research JSON as UTF-8 without BOM and with LF."""

    try:
        text = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise AnalysisError("OUTPUT_JSON", "report is not canonical JSON") from error
    return (text + "\n").encode("utf-8")


def _reject_duplicate_members(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    document: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in document:
            raise DuplicateKeyError(json.dumps(key, ensure_ascii=True))
        document[key] = value
    return document


def _reject_non_finite_number(value: str) -> float:
    raise ValueError(f"non-finite number {value}")


def _parse_bounded_integer(value: str, maximum_digits: int) -> int:
    digit_count = len(value.lstrip("-"))
    if digit_count > maximum_digits:
        raise ValueError(f"integer exceeds {maximum_digits} digits")
    return int(value)


# Time O(n); Space O(1), where n is the JSON byte length.
def _validate_json_lexical_depth(payload: bytes, maximum_depth: int) -> None:
    """Reject excessive structural depth before recursive JSON decoding."""

    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord('"'):
                in_string = False
            continue
        if byte == ord('"'):
            in_string = True
        elif byte in (ord("{"), ord("[")):
            depth += 1
            if depth > maximum_depth:
                raise AnalysisError(
                    "JSON_DEPTH_LIMIT",
                    f"JSON exceeds structural depth {maximum_depth}",
                )
        elif byte in (ord("}"), ord("]")):
            depth -= 1
            if depth < 0:
                break


# Time O(n); Space O(n) worst case, where n is the decoded JSON node count.
def _validate_json_tree(
    root: object,
    limits: ResourceLimits,
    display_path: str,
) -> int:
    stack = [root]
    node_count = 0
    while stack:
        value = stack.pop()
        node_count += 1
        if isinstance(value, str):
            if len(value) > limits.maximum_string_characters:
                raise AnalysisError(
                    "JSON_STRING_LIMIT",
                    f"{display_path} contains a string over "
                    f"{limits.maximum_string_characters} characters",
                )
        elif isinstance(value, dict):
            if len(value) > limits.maximum_collection_items:
                raise AnalysisError(
                    "JSON_COLLECTION_LIMIT",
                    f"{display_path} contains an object over "
                    f"{limits.maximum_collection_items} members",
                )
            stack.extend(value.keys())
            stack.extend(value.values())
        elif isinstance(value, list):
            if len(value) > limits.maximum_collection_items:
                raise AnalysisError(
                    "JSON_COLLECTION_LIMIT",
                    f"{display_path} contains an array over "
                    f"{limits.maximum_collection_items} items",
                )
            stack.extend(value)
        elif value is not None and not isinstance(value, (bool, int, float)):
            raise AnalysisError("JSON_TYPE", f"{display_path} contains an unsupported value")
        if node_count > limits.maximum_json_nodes_per_file:
            return node_count
    return node_count


def _require_mapping(value: object, pointer: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise AnalysisError("CONTRACT_OBJECT", f"{pointer} must be an object")
    return value


def _require_list(value: object, pointer: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise AnalysisError("CONTRACT_ARRAY", f"{pointer} must be an array")
    return value


def _require_string(value: object, pointer: str) -> str:
    if not isinstance(value, str):
        raise AnalysisError("CONTRACT_STRING", f"{pointer} must be a string")
    return value


def _require_integer(value: object, pointer: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalysisError("CONTRACT_INTEGER", f"{pointer} must be an integer")
    return value


def _require_positive_integer(value: object, pointer: str) -> int:
    integer = _require_integer(value, pointer)
    if integer <= 0:
        raise AnalysisError("CONTRACT_POSITIVE", f"{pointer} must be positive")
    return integer


def _optional_positive_integer(value: object, default: int, pointer: str) -> int:
    return default if value is None else _require_positive_integer(value, pointer)


def _require_boolean(value: object, pointer: str) -> bool:
    if not isinstance(value, bool):
        raise AnalysisError("CONTRACT_BOOLEAN", f"{pointer} must be a boolean")
    return value


def repository_root_from_script() -> Path:
    """Resolve the checkout root from this fixed tool location."""

    return Path(__file__).resolve().parents[4]


def _write_output(payload: bytes, output_path: str) -> None:
    if output_path == "-":
        sys.stdout.buffer.write(payload)
        return
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        temporary.write_bytes(payload)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository-root",
        type=Path,
        default=repository_root_from_script(),
        help="Repository checkout root (defaults to the tool's checkout).",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Canonical JSON destination, or '-' for stdout.",
    )
    arguments = parser.parse_args(argv)
    try:
        report = analyze_repository(arguments.repository_root)
        _write_output(canonical_json_bytes(report), arguments.output)
    except (AnalysisError, OSError) as error:
        code = error.code if isinstance(error, AnalysisError) else "IO_ERROR"
        detail = error.detail if isinstance(error, AnalysisError) else "analysis I/O failed"
        diagnostic: JsonValue = {
            "error": {"code": code, "detail": detail},
            "schemaVersion": ANALYSIS_SCHEMA_VERSION,
        }
        sys.stderr.buffer.write(canonical_json_bytes(diagnostic))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
