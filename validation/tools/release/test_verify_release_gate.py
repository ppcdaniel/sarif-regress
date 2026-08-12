#!/usr/bin/env python3
"""Behavioral tests for the tagged release evidence gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_release_gate import GateError, REQUIRED_EVIDENCE_FILES, verify_release_gate


SOURCE_SHA = "a" * 40
FROZEN_SHA = "f" * 40
WORKFLOW_RUN_ID = 123456789
WORKFLOW_RUN_ATTEMPT = 2


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


class ReleaseGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.evidence = self.root / "evidence"
        (self.root / "validation/holdout").mkdir(parents=True)
        (self.root / "validation/history/matcher-v3.1").mkdir(parents=True)
        self.evidence.mkdir()

    def _verify(self, tag: str) -> str:
        return verify_release_gate(
            self.root,
            self.evidence,
            SOURCE_SHA,
            tag,
            WORKFLOW_RUN_ID,
            WORKFLOW_RUN_ATTEMPT,
        )

    def _refresh_outer_manifest(self) -> None:
        manifest = "".join(
            f"{hashlib.sha256((self.evidence / name).read_bytes()).hexdigest()}  {name}\n"
            for name in sorted(REQUIRED_EVIDENCE_FILES)
        )
        (self.evidence / "cross-platform-checksums.sha256").write_text(
            manifest, encoding="ascii", newline="\n")

    def _mutate_json(self, name: str, mutation: object) -> None:
        path = self.evidence / name
        value = json.loads(path.read_text(encoding="utf-8"))
        mutation(value)  # type: ignore[operator]
        path.write_bytes(_json_bytes(value))
        self._refresh_outer_manifest()

    def _write_policy(self, preview: str = "blocked", stable: str = "blocked") -> None:
        def channel(recommendation: str) -> dict[str, object]:
            reasons = [] if recommendation == "ready" else ["test-blocker"]
            return {"recommendation": recommendation, "reasonIds": reasons}

        policy = {
            "$schema": "schemas/release-gate-policy.schema.json",
            "schemaVersion": "1",
            "policyKind": "release-channel-readiness",
            "criteriaDocument": "docs/release-readiness.md#preview-and-stable-criteria",
            "channels": {
                "preview": channel(preview),
                "stable": channel(stable),
            },
        }
        (self.root / "validation/release-gate-policy.json").write_bytes(
            _json_bytes(policy))

    def _write_evidence(
        self,
        *,
        source_sha: str = SOURCE_SHA,
        holdout_recommendation: str = "blocked",
        stable_conditions_met: bool = True,
        safety_override: tuple[str, bool] | None = None,
        development_passed: bool = True,
        active_report_schema_version: str = "3",
        active_report_kind: str = "sarif-regress-exposed-holdout-regression",
        comparison_schema_version: str = "4",
        comparison_report_kind: str = "holdout-external-baseline-comparison",
        delta_schema_version: str = "1",
    ) -> None:
        holdout_manifest = b'{"schemaVersion":"test"}\n'
        (self.root / "validation/holdout/manifest.json").write_bytes(
            holdout_manifest)
        holdout_manifest_hash = hashlib.sha256(holdout_manifest).hexdigest()

        history_report = b'{"report":"matcher-v3.1-history"}\n'
        history_report_path = (
            self.root / "validation/history/matcher-v3.1/sarif-regress-holdout.json")
        history_report_path.write_bytes(history_report)
        history_report_hash = hashlib.sha256(history_report).hexdigest()
        history_manifest = (
            f"{history_report_hash}  sarif-regress-holdout.json\n".encode("ascii"))
        history_manifest_path = (
            self.root / "validation/history/matcher-v3.1/checksums.sha256")
        history_manifest_path.write_bytes(history_manifest)
        history_manifest_hash = hashlib.sha256(history_manifest).hexdigest()

        evaluation_metadata = {
            "repositoryCommitSha": FROZEN_SHA,
            "holdoutManifestSha256": holdout_manifest_hash,
        }
        evaluation_metadata_path = (
            self.root / "validation/holdout/evaluation-metadata.json")
        evaluation_metadata_path.write_bytes(_json_bytes(evaluation_metadata))
        evaluation_metadata_hash = hashlib.sha256(
            evaluation_metadata_path.read_bytes()).hexdigest()

        report_evaluation = {
            "repositoryCommitSha": FROZEN_SHA,
            "holdoutManifestSha256": holdout_manifest_hash,
            "matcherAlgorithmVersion": "sarifregress/matcher/v3.2",
        }
        report_payloads = {
            "sarif-regress-holdout.json": _json_bytes({
                "schemaVersion": active_report_schema_version,
                "reportKind": active_report_kind,
                "evaluation": report_evaluation,
            }),
            "sarif-multitool-baseline.json": _json_bytes({
                "report": "multitool",
                "evaluation": report_evaluation,
            }),
        }
        for name, payload in report_payloads.items():
            (self.evidence / name).write_bytes(payload)

        digest = lambda name: hashlib.sha256(  # noqa: E731 - compact fixture binding
            (self.evidence / name).read_bytes()).hexdigest()
        base_reports = {
            "sarifRegressHoldoutSha256": digest("sarif-regress-holdout.json"),
            "sarifMultitoolBaselineSha256": digest("sarif-multitool-baseline.json"),
        }
        manifest_hash = holdout_manifest_hash
        metadata_hash = evaluation_metadata_hash

        delta = {
            "schemaVersion": delta_schema_version,
            "reportKind": "matcher-v3.1-to-v3.2-delta",
            "inputHashes": {
                "matcherV31HistoryChecksumManifestSha256": history_manifest_hash,
                "matcherV31ReportSha256": history_report_hash,
                "matcherV32ReportSha256": base_reports[
                    "sarifRegressHoldoutSha256"],
                "holdoutManifestSha256": manifest_hash,
            },
        }
        (self.evidence / "v3.1-to-v3.2-delta.json").write_bytes(
            _json_bytes(delta))
        base_reports["v31ToV32DeltaSha256"] = digest(
            "v3.1-to-v3.2-delta.json")

        attestation = {
            "schemaVersion": "4",
            "repository": "ppcdaniel/sarif-regress",
            "repositoryCommitSha": FROZEN_SHA,
            "holdoutManifestSha256": manifest_hash,
            "evaluationMetadataSha256": metadata_hash,
            "baseReports": base_reports,
            "githubActions": {
                "workflowPath": ".github/workflows/holdout-validation.yml",
                "runId": WORKFLOW_RUN_ID,
                "runAttempt": WORKFLOW_RUN_ATTEMPT,
                "runUrl": (
                    "https://github.com/ppcdaniel/sarif-regress/actions/runs/"
                    f"{WORKFLOW_RUN_ID}"),
                "workflowHeadSha": source_sha,
                "workflowConclusion": "success",
                "coordinatorJobConclusion": "success",
                "coordinatorJobName": "Compare Linux and Windows normalized bytes",
            },
            "artifacts": {
                "linux": {
                    "name": "holdout-linux",
                    "artifactId": 101,
                    "archiveSha256": "d" * 64,
                    "reportDigests": base_reports,
                },
                "windows": {
                    "name": "holdout-windows",
                    "artifactId": 102,
                    "archiveSha256": "e" * 64,
                    "reportDigests": base_reports,
                },
            },
            "byteIdentity": {
                "sarifRegressHoldout": True,
                "sarifMultitoolBaseline": True,
                "v31ToV32Delta": True,
            },
        }
        (self.evidence / "cross-platform-attestation.json").write_bytes(
            _json_bytes(attestation))

        conditions = {name: True for name in (
            "precisionMet",
            "recallMet",
            "allProducerPrecisionMet",
            "allProducerRecallMet",
            "zeroIncorrectAmbiguityMatches",
            "noUnexplainedIngestionFailures",
            "noStructuralFailures",
            "completeLabelGraphSatisfied",
            "crossPlatformByteIdentity",
            "evaluationCompleted",
            "everyChangedDecisionExplained",
        )}
        if not stable_conditions_met:
            conditions["recallMet"] = False
            conditions["allProducerRecallMet"] = False
            conditions["completeLabelGraphSatisfied"] = False
        if safety_override is not None:
            conditions[safety_override[0]] = safety_override[1]
        comparison = {
            "schemaVersion": comparison_schema_version,
            "reportKind": comparison_report_kind,
            "evaluation": report_evaluation,
            "releaseRecommendation": holdout_recommendation,
            "thresholds": {
                "minimumPrecision": 0.95,
                "minimumRecall": 0.90,
                "minimumPerProducerPrecision": 0.95,
                "minimumPerProducerRecall": 0.80,
                "maximumIncorrectlyAutoMatchedAmbiguousCases": 0,
                "maximumUnexplainedIngestionFailures": 0,
                "maximumStructuralFailures": 0,
                "requireCompleteLabelGraph": True,
                "requireCrossPlatformByteIdentity": True,
                "requireCompletedEvaluation": True,
                "requireChangedDecisionExplanations": True,
            },
            "releaseConditions": conditions,
            "reportHashes": {
                "holdoutManifestSha256": manifest_hash,
                "evaluationMetadataSha256": metadata_hash,
                "sarifRegressReportSha256": base_reports[
                    "sarifRegressHoldoutSha256"],
                "sarifMultitoolBaselineReportSha256": base_reports[
                    "sarifMultitoolBaselineSha256"],
                "matcherV31ReportSha256": history_report_hash,
                "v31ToV32DeltaReportSha256": base_reports[
                    "v31ToV32DeltaSha256"],
            },
        }
        (self.evidence / "comparison-summary.json").write_bytes(
            _json_bytes(comparison))

        development = {
            "passed": development_passed,
            "failures": [] if development_passed else ["fixture failure"],
        }
        (self.evidence / "development-corpus-report.json").write_bytes(
            _json_bytes(development))

        repository_manifest_entries = {
            "validation/expected/sarif-multitool-baseline.json": base_reports[
                "sarifMultitoolBaselineSha256"],
            "validation/expected/sarif-regress-holdout.json": base_reports[
                "sarifRegressHoldoutSha256"],
            "validation/expected/v3.1-to-v3.2-delta.json": base_reports[
                "v31ToV32DeltaSha256"],
            "validation/history/matcher-v3.1/checksums.sha256": history_manifest_hash,
            "validation/history/matcher-v3.1/sarif-regress-holdout.json":
                history_report_hash,
            "validation/holdout/evaluation-metadata.json": metadata_hash,
            "validation/holdout/manifest.json": manifest_hash,
        }
        repository_manifest = "".join(
            f"{repository_manifest_entries[name]}  {name}\n"
            for name in sorted(repository_manifest_entries)
        )
        (self.evidence / "checksums.sha256").write_text(
            repository_manifest, encoding="ascii", newline="\n")

        for name in REQUIRED_EVIDENCE_FILES:
            path = self.evidence / name
            if not path.exists():
                path.write_bytes((name + "\n").encode("ascii"))
        self._refresh_outer_manifest()

    def test_preview_requires_explicit_channel_readiness(self) -> None:
        self._write_policy(preview="blocked")
        self._write_evidence()
        with self.assertRaisesRegex(GateError, "preview release is blocked"):
            self._verify("v0.1.0-rc.1")

    def test_preview_can_accept_safe_holdout_below_stable_thresholds(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(
            holdout_recommendation="blocked",
            stable_conditions_met=False,
        )
        self.assertEqual(
            self._verify("v0.1.0-rc.1"),
            "preview",
        )

    def test_stable_requires_holdout_ready(self) -> None:
        self._write_policy(stable="ready")
        self._write_evidence(holdout_recommendation="blocked")
        with self.assertRaisesRegex(GateError, "holdout recommendation"):
            self._verify("v0.1.0")

    def test_stable_passes_only_when_both_sources_are_ready(self) -> None:
        self._write_policy(stable="ready")
        self._write_evidence(holdout_recommendation="ready")
        self.assertEqual(
            self._verify("v0.1.0"),
            "stable",
        )

    def test_build_metadata_alone_still_selects_stable(self) -> None:
        self._write_policy(stable="ready")
        self._write_evidence(holdout_recommendation="ready")
        self.assertEqual(self._verify("v0.1.0+build.7"), "stable")

    def test_prerelease_with_build_metadata_selects_preview(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(
            holdout_recommendation="blocked",
            stable_conditions_met=False,
        )
        self.assertEqual(self._verify("v0.1.0-rc.1+build.7"), "preview")

    def test_exact_head_mismatch_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(source_sha="f" * 40)
        with self.assertRaisesRegex(GateError, "exact tagged commit"):
            self._verify("v0.1.0-rc.1")

    def test_failed_safety_condition_is_rejected_for_preview(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(
            safety_override=("zeroIncorrectAmbiguityMatches", False))
        with self.assertRaisesRegex(GateError, "safety conditions failed"):
            self._verify("v0.1.0-rc.1")

    def test_stable_rechecks_every_threshold_condition(self) -> None:
        self._write_policy(stable="ready")
        self._write_evidence(
            holdout_recommendation="ready",
            stable_conditions_met=False,
        )
        with self.assertRaisesRegex(GateError, "Stable holdout conditions failed"):
            self._verify("v0.1.0")

    def test_failed_development_corpus_is_rejected_for_preview(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(development_passed=False)
        with self.assertRaisesRegex(GateError, "Development corpus is not green"):
            self._verify("v0.1.0-rc.1")

    def test_attestation_must_bind_current_run_and_attempt(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "cross-platform-attestation.json",
            lambda value: value["githubActions"].update({
                "runAttempt": WORKFLOW_RUN_ATTEMPT + 1,
            }),
        )
        with self.assertRaisesRegex(GateError, "current workflow run attempt"):
            self._verify("v0.1.0-rc.1")

    def test_failed_workflow_conclusion_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "cross-platform-attestation.json",
            lambda value: value["githubActions"].update({
                "workflowConclusion": "failure",
            }),
        )
        with self.assertRaisesRegex(GateError, "workflow did not attest"):
            self._verify("v0.1.0-rc.1")

    def test_failed_coordinator_conclusion_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "cross-platform-attestation.json",
            lambda value: value["githubActions"].update({
                "coordinatorJobConclusion": "failure",
            }),
        )
        with self.assertRaisesRegex(GateError, "coordinator did not attest"):
            self._verify("v0.1.0-rc.1")

    def test_obsolete_active_report_schema_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(active_report_schema_version="2")
        with self.assertRaisesRegex(GateError, "unexpected schema version"):
            self._verify("v0.1.0-rc.1")

    def test_obsolete_active_report_claim_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(
            active_report_kind="sarif-regress-independent-holdout")
        with self.assertRaisesRegex(GateError, "repeats an obsolete claim"):
            self._verify("v0.1.0-rc.1")

    def test_obsolete_comparison_schema_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(comparison_schema_version="3")
        with self.assertRaisesRegex(GateError, "Comparison summary.*schema version"):
            self._verify("v0.1.0-rc.1")

    def test_unexpected_comparison_report_kind_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(comparison_report_kind="obsolete-comparison")
        with self.assertRaisesRegex(GateError, "Comparison summary.*report kind"):
            self._verify("v0.1.0-rc.1")

    def test_unexpected_matcher_delta_schema_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence(delta_schema_version="2")
        with self.assertRaisesRegex(GateError, "Matcher delta.*schema version"):
            self._verify("v0.1.0-rc.1")

    def test_partial_byte_identity_attestation_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "cross-platform-attestation.json",
            lambda value: value["byteIdentity"].pop("v31ToV32Delta"),
        )
        with self.assertRaisesRegex(GateError, "byte identity keys differ"):
            self._verify("v0.1.0-rc.1")

    def test_zero_producer_archive_digest_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "cross-platform-attestation.json",
            lambda value: value["artifacts"]["linux"].update({
                "archiveSha256": "0" * 64,
            }),
        )
        with self.assertRaisesRegex(GateError, "lowercase SHA-256 digest"):
            self._verify("v0.1.0-rc.1")

    def test_extra_release_condition_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "comparison-summary.json",
            lambda value: value["releaseConditions"].update({"futureGate": True}),
        )
        with self.assertRaisesRegex(GateError, "release conditions keys differ"):
            self._verify("v0.1.0-rc.1")

    def test_lowered_release_threshold_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        self._mutate_json(
            "comparison-summary.json",
            lambda value: value["thresholds"].update({"minimumRecall": 0.50}),
        )
        with self.assertRaisesRegex(GateError, "differs from the fixed gate"):
            self._verify("v0.1.0-rc.1")

    def test_inner_checksum_manifest_must_bind_matcher_history(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        path = self.evidence / "checksums.sha256"
        text = path.read_text(encoding="ascii")
        text = text.replace(
            next(line.split("  ", 1)[0] for line in text.splitlines()
                 if line.endswith(
                     "validation/history/matcher-v3.1/sarif-regress-holdout.json")),
            "0" * 64,
            1,
        )
        path.write_text(text, encoding="ascii", newline="\n")
        self._refresh_outer_manifest()
        with self.assertRaisesRegex(GateError, "does not bind"):
            self._verify("v0.1.0-rc.1")

    def test_unexpected_evidence_entry_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        (self.evidence / "unexpected.txt").write_text(
            "unexpected\n", encoding="utf-8")
        with self.assertRaisesRegex(GateError, "Evidence root differs"):
            self._verify("v0.1.0-rc.1")

    def test_missing_composite_coordinator_entry_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        (
            self.evidence
            / "sparse-experiment-release-composite-projection.json"
        ).unlink()
        with self.assertRaisesRegex(GateError, "Evidence root differs"):
            self._verify("v0.1.0-rc.1")

    def test_checksum_tampering_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        with (self.evidence / "comparison-summary.json").open("ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(GateError, "checksum mismatch"):
            self._verify("v0.1.0-rc.1")

    def test_noncanonical_tag_is_rejected(self) -> None:
        self._write_policy(preview="ready")
        self._write_evidence()
        with self.assertRaisesRegex(GateError, "Semantic Version"):
            self._verify("v01.0.0-rc.1")


if __name__ == "__main__":
    unittest.main()
