#!/usr/bin/env python3
"""Adversarial tests for the bounded duplicate-symmetry analyzer."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from analyze_duplicate_symmetry import (
    FIXED_OBSERVATIONS,
    AnalysisError,
    BoundedRepositoryReader,
    ResourceLimits,
    SourceFeatureExtractor,
    analyze_repository,
    canonical_json_bytes,
    extract_all_features,
    fixed_observation_projection,
    repository_root_from_script,
    strip_comments_preserving_lines,
    verify_fixed_observations,
)


class StrictInputTests(unittest.TestCase):
    """Hostile input must fail before it can influence an observation."""

    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="sarif-regress-duplicate-symmetry-"
        )
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_duplicate_json_members_are_rejected(self) -> None:
        (self.root / "duplicate.json").write_text(
            '{"rule":"first","rule":"second"}',
            encoding="utf-8",
            newline="\n",
        )
        reader = BoundedRepositoryReader(self.root)

        with self.assertRaises(AnalysisError) as raised:
            reader.read_json("duplicate.json")

        self.assertEqual("JSON_DUPLICATE_KEY", raised.exception.code)

    def test_json_depth_and_file_byte_limits_are_enforced(self) -> None:
        (self.root / "deep.json").write_text(
            "[[[[0]]]]",
            encoding="utf-8",
            newline="\n",
        )
        depth_reader = BoundedRepositoryReader(
            self.root,
            ResourceLimits(maximum_json_depth=3),
        )
        with self.assertRaises(AnalysisError) as depth_error:
            depth_reader.read_json("deep.json")
        self.assertEqual("JSON_DEPTH_LIMIT", depth_error.exception.code)

        (self.root / "large.json").write_text(
            '{"payload":"too-large"}',
            encoding="utf-8",
            newline="\n",
        )
        byte_reader = BoundedRepositoryReader(
            self.root,
            ResourceLimits(maximum_json_file_bytes=8),
        )
        with self.assertRaises(AnalysisError) as byte_error:
            byte_reader.read_json("large.json")
        self.assertEqual("INPUT_FILE_LIMIT", byte_error.exception.code)

    def test_aggregate_input_and_source_token_limits_are_enforced(self) -> None:
        (self.root / "first.java").write_text(
            "one two\n",
            encoding="utf-8",
            newline="\n",
        )
        (self.root / "second.java").write_text(
            "three four\n",
            encoding="utf-8",
            newline="\n",
        )
        aggregate_reader = BoundedRepositoryReader(
            self.root,
            ResourceLimits(maximum_total_input_bytes=12),
        )
        aggregate_reader.read_source("first.java")
        with self.assertRaises(AnalysisError) as aggregate_error:
            aggregate_reader.read_source("second.java")
        self.assertEqual("INPUT_TOTAL_BYTE_LIMIT", aggregate_error.exception.code)

        token_reader = BoundedRepositoryReader(
            self.root,
            ResourceLimits(maximum_source_tokens_per_file=2),
        )
        extractor = SourceFeatureExtractor(token_reader)
        with self.assertRaises(AnalysisError) as token_error:
            extractor.model_from_text(
                "synthetic.java",
                "alpha beta gamma\n",
                account_tokens=True,
            )
        self.assertEqual("SOURCE_TOKEN_LIMIT", token_error.exception.code)


class MarkerMutationTests(unittest.TestCase):
    """Ground-truth marker text must be erased before feature construction."""

    def test_same_length_comment_marker_mutation_is_feature_invariant(self) -> None:
        source = (
            "final class Example {\n"
            "    void run(Exception failure) {\n"
            "        // HOLDOUT:identity-001\n"
            "        failure.printStackTrace();\n"
            "    }\n"
            "}\n"
        )
        mutated = source.replace("HOLDOUT:", "MUTATED:")
        with tempfile.TemporaryDirectory(
            prefix="sarif-regress-marker-mutation-"
        ) as temporary_directory:
            reader = BoundedRepositoryReader(Path(temporary_directory))
            extractor = SourceFeatureExtractor(reader)
            original_model = extractor.model_from_text(
                "original.java", source, account_tokens=False
            )
            mutated_model = extractor.model_from_text(
                "mutated.java", mutated, account_tokens=False
            )
            code_mutated_model = extractor.model_from_text(
                "code-mutated.java",
                source.replace("printStackTrace", "getMessage"),
                account_tokens=False,
            )

        self.assertEqual(source.count("\n"), strip_comments_preserving_lines(source).count("\n"))
        self.assertEqual(original_model.feature_digest(), mutated_model.feature_digest())
        self.assertNotEqual(
            original_model.feature_digest(),
            code_mutated_model.feature_digest(),
        )


class FrozenRepositoryTests(unittest.TestCase):
    """The committed boundary must remain byte-stable and exactly scored."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.repository_root = repository_root_from_script()
        cls.report = analyze_repository(cls.repository_root)

    def test_feature_extraction_opens_no_label_document(self) -> None:
        reader = BoundedRepositoryReader(self.repository_root)
        source_extractor = SourceFeatureExtractor(reader)

        extract_all_features(reader, source_extractor)

        self.assertTrue(reader.input_paths)
        self.assertFalse(
            any(path.endswith("/labels.json") for path in reader.input_paths),
            reader.input_paths,
        )

    def test_frozen_metrics_and_lifecycle_sets_match_exactly(self) -> None:
        self.assertEqual(FIXED_OBSERVATIONS, fixed_observation_projection(self.report))
        self.assertEqual(
            "passed",
            self.report["fixedObservationVerification"]["status"],
        )

    def test_legacy_symmetry_counts_are_exact(self) -> None:
        groups = self.report["symmetryBoundary"]["legacyGroups"]
        by_method = {
            next(
                token
                for token in group["scopeHeader"]
                if token in {"ambiguousCases", "exactCases"}
            ): group
            for group in groups
            if any(
                token in {"ambiguousCases", "exactCases"}
                for token in group["scopeHeader"]
            )
        }

        ambiguous = by_method["ambiguousCases"]
        exact = by_method["exactCases"]
        self.assertEqual((2, 4, 2), (
            ambiguous["baselineCount"],
            ambiguous["completeSemanticEdgeCount"],
            ambiguous["maximumCardinalityAssignmentCount"],
        ))
        self.assertEqual("refuse", ambiguous["oracleOutcome"])
        self.assertEqual((5, 25, 120), (
            exact["baselineCount"],
            exact["completeSemanticEdgeCount"],
            exact["maximumCardinalityAssignmentCount"],
        ))
        self.assertEqual("pair", exact["oracleOutcome"])
        self.assertTrue(ambiguous["commentFreeScopeIdentity"])
        self.assertTrue(exact["commentFreeScopeIdentity"])

    def test_marker_mutation_is_invariant_for_every_legacy_snapshot(self) -> None:
        marker = self.report["markerMutationInvariance"]
        self.assertEqual(8, marker["filesChecked"])
        self.assertEqual(60, marker["markerOccurrences"])
        self.assertTrue(marker["invariant"])
        self.assertTrue(all(file["invariant"] for file in marker["files"]))

    def test_canonical_report_bytes_are_repeatable(self) -> None:
        repeated = analyze_repository(self.repository_root)
        first_bytes = canonical_json_bytes(self.report)
        second_bytes = canonical_json_bytes(repeated)

        self.assertEqual(first_bytes, second_bytes)
        self.assertTrue(first_bytes.endswith(b"\n"))
        self.assertFalse(first_bytes.startswith(b"\xef\xbb\xbf"))

    def test_fixed_metric_drift_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.report)
        mutated["scores"]["legacy"]["sourceOrderControl"]["relationships"][
            "falsePositives"
        ] = 1

        with self.assertRaises(AnalysisError) as raised:
            verify_fixed_observations(mutated)

        self.assertEqual("FIXED_OBSERVATION_MISMATCH", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
