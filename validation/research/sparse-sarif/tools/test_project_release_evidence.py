#!/usr/bin/env python3
"""Self-tests for producer-agnostic release evidence projection."""

from __future__ import annotations

import copy
import unittest

from project_release_evidence import DEFECT_FIELDS, project_release_evidence


def _metrics(true_positives: int, relationships: int) -> dict[str, object]:
    false_negatives = relationships - true_positives
    precision = 1.0
    recall = round(true_positives / relationships, 6)
    f1 = round(2 * precision * recall / (precision + recall), 6)
    return {
        "labelledMatches": true_positives,
        "truePositives": true_positives,
        "falsePositives": 0,
        "falseNegatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        **{field: 0 for field in DEFECT_FIELDS},
    }


def _reports() -> tuple[dict[str, object], dict[str, object]]:
    producer_ids = ("alpha", "beta", "gamma")
    producers = [
        {"producerId": producer_id, "metrics": _metrics(25, 25)}
        for producer_id in producer_ids
    ]
    aggregate = _metrics(75, 75)
    return (
        {
            "aggregate": {"labelledRelationships": 75, **aggregate},
            "producers": producers,
        },
        {
            "passed": True,
            "failures": [],
            "aggregate": {"silentAmbiguousMatches": 0},
        },
    )


class ReleaseProjectionTests(unittest.TestCase):
    def test_projection_derives_classification_regressions(self) -> None:
        holdout, development = _reports()
        projected = project_release_evidence(
            holdout,
            development,
            producer_order=("alpha", "beta", "gamma"),
            relationships_per_producer=25,
        )
        self.assertIsNotNone(projected)
        assert projected is not None
        self.assertEqual(
            [0, 0, 0],
            [
                producer["regressions"]
                for producer in projected["holdout"]["byProducer"]
            ],
        )

        mutated = copy.deepcopy(holdout)
        mutated["producers"][1]["metrics"]["classificationMismatches"] = 1
        projected = project_release_evidence(
            mutated,
            development,
            producer_order=("alpha", "beta", "gamma"),
            relationships_per_producer=25,
        )
        self.assertIsNotNone(projected)
        assert projected is not None
        self.assertEqual(
            1,
            projected["holdout"]["byProducer"][1]["regressions"],
        )

    def test_projection_rejects_metric_inconsistency(self) -> None:
        holdout, development = _reports()
        holdout["aggregate"]["recall"] = 0.5
        self.assertIsNone(
            project_release_evidence(
                holdout,
                development,
                producer_order=("alpha", "beta", "gamma"),
                relationships_per_producer=25,
            )
        )


if __name__ == "__main__":
    unittest.main()
