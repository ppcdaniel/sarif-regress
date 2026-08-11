#!/usr/bin/env python3
"""Build a producer-agnostic release-gate projection from exact reports."""

from __future__ import annotations

from collections.abc import Mapping, Sequence


DEFECT_FIELDS = (
    "classificationMismatches",
    "incorrectNewClassifications",
    "incorrectResolvedClassifications",
    "unexpectedAmbiguityRefusals",
    "incorrectlyAutoMatchedAmbiguousCases",
    "ingestionFailures",
    "structuralFailures",
)


def _rate(value: int, denominator: int) -> float:
    return round(value / denominator, 6) if denominator else 1.0


def _metric(value: object, relationships: int) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    count_keys = (
        "labelledMatches",
        "truePositives",
        "falsePositives",
        "falseNegatives",
    )
    if any(
        type(value.get(key)) is not int or value[key] < 0
        for key in count_keys
    ):
        return None
    true_positives = value["truePositives"]
    false_positives = value["falsePositives"]
    false_negatives = value["falseNegatives"]
    assert isinstance(true_positives, int)
    assert isinstance(false_positives, int)
    assert isinstance(false_negatives, int)
    accepted = true_positives + false_positives
    if (
        accepted != value["labelledMatches"]
        or true_positives + false_negatives != relationships
    ):
        return None
    precision = _rate(true_positives, accepted)
    recall = _rate(true_positives, relationships)
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if precision + recall
        else 0.0
    )
    observed_rates = (value.get("precision"), value.get("recall"), value.get("f1"))
    if any(
        not isinstance(item, (int, float)) or isinstance(item, bool)
        for item in observed_rates
    ) or tuple(observed_rates) != (precision, recall, f1):
        return None
    return {
        "acceptedPairs": accepted,
        "truePositives": true_positives,
        "falsePositives": false_positives,
        "falseNegatives": false_negatives,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def project_release_evidence(
    holdout: object,
    development: object,
    *,
    producer_order: Sequence[str],
    relationships_per_producer: int,
) -> dict[str, object] | None:
    """Project exact reports while deriving every producer regression count."""

    if (
        not isinstance(holdout, dict)
        or not isinstance(development, dict)
        or not producer_order
        or len(set(producer_order)) != len(producer_order)
        or any(not item for item in producer_order)
        or relationships_per_producer <= 0
    ):
        return None
    relationships = len(producer_order) * relationships_per_producer
    aggregate = holdout.get("aggregate")
    producers = holdout.get("producers")
    if (
        not isinstance(aggregate, dict)
        or aggregate.get("labelledRelationships") != relationships
        or not isinstance(producers, list)
    ):
        return None
    projected_aggregate = _metric(aggregate, relationships)
    if projected_aggregate is None:
        return None

    producer_map: dict[str, Mapping[str, object]] = {}
    for producer in producers:
        if not isinstance(producer, dict):
            return None
        producer_id = producer.get("producerId")
        producer_metrics = producer.get("metrics")
        if (
            not isinstance(producer_id, str)
            or producer_id in producer_map
            or not isinstance(producer_metrics, dict)
        ):
            return None
        producer_map[producer_id] = producer_metrics
    if set(producer_map) != set(producer_order):
        return None

    projected_producers: list[dict[str, object]] = []
    for producer_id in producer_order:
        source = producer_map[producer_id]
        projected_metrics = _metric(source, relationships_per_producer)
        if projected_metrics is None or any(
            type(source.get(field)) is not int or source[field] < 0
            for field in DEFECT_FIELDS
        ):
            return None
        projected_producers.append(
            {
                "producerFamily": producer_id,
                "metrics": projected_metrics,
                "regressions": sum(int(source[field]) for field in DEFECT_FIELDS),
            }
        )

    for key in ("acceptedPairs", "truePositives", "falsePositives", "falseNegatives"):
        if projected_aggregate[key] != sum(
            int(item["metrics"][key]) for item in projected_producers
        ):
            return None

    development_aggregate = development.get("aggregate")
    failures = development.get("failures")
    if (
        type(development.get("passed")) is not bool
        or not isinstance(development_aggregate, dict)
        or type(development_aggregate.get("silentAmbiguousMatches")) is not int
        or development_aggregate["silentAmbiguousMatches"] < 0
        or not isinstance(failures, list)
    ):
        return None
    ingestion_failures = aggregate.get("ingestionFailures")
    structural_failures = aggregate.get("structuralFailures")
    if (
        type(ingestion_failures) is not int
        or ingestion_failures < 0
        or type(structural_failures) is not int
        or structural_failures < 0
    ):
        return None
    return {
        "holdout": {
            "relationshipCount": relationships,
            "metrics": projected_aggregate,
            "byProducer": projected_producers,
            "ingestionFailures": ingestion_failures,
            "structuralFailures": structural_failures,
        },
        "developmentCorpus": {
            "passed": development["passed"],
            "regressions": len(failures),
            "silentlyMatchedAmbiguity": development_aggregate[
                "silentAmbiguousMatches"
            ],
        },
    }
