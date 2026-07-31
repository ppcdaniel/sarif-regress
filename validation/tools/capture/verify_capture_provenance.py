#!/usr/bin/env python3
"""Cross-check committed capture provenance against the validated manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

from normalize_gitleaks_sarif import ALGORITHM_VERSION
from project_holdout import ProjectionError, _read_bounded_json


SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
COMMIT_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
EXPECTED_PRODUCERS: Final = frozenset({"gitleaks", "pmd", "semgrep"})
EXPECTED_PINS: Final = {
    "gitleaks": {
        "version": "8.30.1",
        "sourceCommit": "83d9cd684c87d95d656c1458ef04895a7f1cbd8e",
        "artifactSha256": (
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
        ),
        "artifactBytes": 8230402,
    },
    "pmd": {
        "version": "7.26.0",
        "sourceCommit": "8fd38edf285a33e1164f66205ebe243441db9557",
        "artifactSha256": (
            "9f55cb7ff0e9f9a66dd2f005eaa370e84c8a4cd971b134aa14a930c4a283ebc9"
        ),
        "artifactBytes": 73646044,
    },
    "semgrep": {
        "version": "1.172.0",
        "sourceCommit": "651f37efa397bf066e1cf627414eeabe40b07e27",
        "artifactSha256": (
            "d8b94af4266a575287ad2cd844573743ab4fe58f6bfb6d9229327807937eade3"
        ),
        "artifactBytes": 69575334,
    },
}
EXPECTED_COMMAND_EVIDENCE: Final = {
    "gitleaks": {
        "versionCommand": "gitleaks version",
        "helpCommand": "gitleaks dir --help",
        "helpSha256": (
            "ff55bf949d8ac8354e133f09c8be4ccac32cf82ec3a01446e2f31cbe20857a86"
        ),
        "versionOutputSha256": (
            "c9fd9ccb6682c54b5fcb0363757b6c6873564e7c067f70b3b5581b611528b9f4"
        ),
        "installation": (
            "Verify the official checksum manifest and archive size/SHA-256, "
            "run python3 -B validation/tools/capture/extract_tar.py --archive "
            "<archive> --destination <temporary-tools>/gitleaks --member "
            "gitleaks, then set mode 0755."
        ),
        "execution": (
            "gitleaks dir . --config "
            "validation/holdout/cases/gitleaks/producer-input/gitleaks.toml "
            "--exit-code 0 --log-level error --no-banner --no-color "
            "--redact=100 --report-format sarif --report-path "
            "<producer-capture>"
        ),
    },
    "pmd": {
        "versionCommand": "pmd --version",
        "helpCommand": "pmd check --help",
        "helpSha256": (
            "babf2b1e17bddd7611cc4882b9686c207e2b73fee3e3053276b3455e6c890b91"
        ),
        "installation": (
            "Verify archive size/SHA-256, extract with "
            "validation/tools/capture/extract_zip.py, then set the bundled "
            "bin/pmd launcher mode to 0755."
        ),
        "execution": (
            "pmd check --dir . --format sarif --no-cache "
            "--no-fail-on-violation --no-progress --relativize-paths-with "
            "<controlled-source-root> --report-file <raw-capture> --rulesets "
            "validation/holdout/cases/pmd/producer-input/pmd-ruleset.xml "
            "--threads 0 --use-version java-17"
        ),
    },
    "semgrep": {
        "versionCommand": (
            "<temporary-tools>/semgrep-environment/bin/python -I -B "
            "<repository-root>/validation/tools/capture/run_semgrep.py "
            "--semgrep-script <temporary-tools>/semgrep-environment/bin/semgrep "
            "--library-directory <temporary-tools>/semgrep-environment/lib/"
            "python3.12/site-packages/semgrep/bin/libs -- --legacy --version"
        ),
        "versionOutputSha256": (
            "82e4502ffa8035703c9a3c28b596f2977de9a0aee1f707e8bd524878f01939b9"
        ),
        "helpCommand": (
            "<temporary-tools>/semgrep-environment/bin/python -I -B "
            "<repository-root>/validation/tools/capture/run_semgrep.py "
            "--semgrep-script <temporary-tools>/semgrep-environment/bin/semgrep "
            "--library-directory <temporary-tools>/semgrep-environment/lib/"
            "python3.12/site-packages/semgrep/bin/libs -- --legacy scan --help"
        ),
        "helpSha256": (
            "b63d6e12f56f512a1c5cd1f9d9d931056c103c06dfec971b1ff26e12c2c16582"
        ),
        "executionMode": (
            "The runner explicitly selects Semgrep's --legacy mode; every "
            "packaged native core invocation uses the reviewed loader without "
            "exporting wheel libraries to Python."
        ),
        "execution": (
            "<temporary-tools>/semgrep-environment/bin/python -I -B "
            "<repository-root>/validation/tools/capture/run_semgrep.py "
            "--semgrep-script <temporary-tools>/semgrep-environment/bin/semgrep "
            "--library-directory <temporary-tools>/semgrep-environment/lib/"
            "python3.12/site-packages/semgrep/bin/libs -- --legacy scan --config "
            "validation/holdout/cases/semgrep/producer-input/"
            "semgrep-rules.yml --disable-version-check --metrics=off "
            "--no-git-ignore --no-rewrite-rule-ids --oss-only --quiet "
            "--sarif --strict --output <raw-capture> ."
        ),
    },
}


class ProvenanceError(RuntimeError):
    """Raised when capture provenance is missing or inconsistent."""


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProvenanceError(f"{context} must be an object.")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProvenanceError(f"{context} must be an array.")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProvenanceError(f"{context} must be a non-empty string.")
    return value


def _require_exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    context: str,
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required)
    if missing or extra:
        raise ProvenanceError(
            f"{context} fields differ; missing={missing}, extra={extra}."
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_repository_file(repository_root: Path, relative: str) -> Path:
    if "\\" in relative or relative.startswith("/"):
        raise ProvenanceError(f"Declared path is not repository-relative: {relative}")
    path = repository_root.joinpath(*relative.split("/"))
    if path.is_symlink() or not path.is_file():
        raise ProvenanceError(
            f"Declared provenance file is missing or unsafe: {relative}"
        )
    try:
        path.resolve(strict=True).relative_to(repository_root)
    except ValueError as error:
        raise ProvenanceError(
            f"Declared provenance file escapes the repository: {relative}"
        ) from error
    return path


def verify(repository_root: Path) -> None:
    repository_root = repository_root.resolve(strict=True)
    manifest = _object(
        _read_bounded_json(
            repository_root / "validation" / "holdout" / "manifest.json"
        ),
        "manifest",
    )
    provenance = _object(
        _read_bounded_json(
            repository_root
            / "validation"
            / "tools"
            / "capture"
            / "capture-provenance.json"
        ),
        "capture provenance",
    )
    _require_exact_keys(
        provenance,
        {
            "schemaVersion",
            "captureDate",
            "captureEnvironment",
            "captureScript",
            "reproductionCommand",
            "projectionScript",
            "gitleaksOrderingNormalization",
            "projectionVerificationScript",
            "sourceVerificationScript",
            "semgrepRunnerScript",
            "semgrepCoreLoaderScript",
            "producers",
        },
        "capture provenance",
    )
    if provenance["schemaVersion"] != "1":
        raise ProvenanceError("Capture provenance schemaVersion must be '1'.")

    environment = _object(
        provenance["captureEnvironment"],
        "captureEnvironment",
    )
    _require_exact_keys(
        environment,
        {
            "operatingSystem",
            "architecture",
            "pythonVersion",
            "javaDistribution",
            "javaVersion",
            "verifiedRecaptureRunnerImage",
            "glibcVersion",
            "dynamicLoader",
            "libc",
            "networkPolicy",
        },
        "captureEnvironment",
    )
    expected_environment = {
        "operatingSystem": "Linux",
        "architecture": "x86-64",
        "pythonVersion": "3.12.13",
        "javaDistribution": "Eclipse Temurin",
        "javaVersion": "17.0.19+10",
        "glibcVersion": "2.39",
    }
    for field, expected in expected_environment.items():
        if environment[field] != expected:
            raise ProvenanceError(
                f"Capture environment {field} must remain {expected!r}."
            )
    runner_image = _object(
        environment["verifiedRecaptureRunnerImage"],
        "verifiedRecaptureRunnerImage",
    )
    expected_runner_image = {
        "label": "ubuntu-24.04",
        "imageOs": "ubuntu24",
        "imageVersion": "20260720.247.2",
    }
    _require_exact_keys(
        runner_image,
        set(expected_runner_image),
        "verifiedRecaptureRunnerImage",
    )
    if runner_image != expected_runner_image:
        raise ProvenanceError("Verified recapture runner image differs.")
    dynamic_loader = _object(
        environment["dynamicLoader"],
        "captureEnvironment.dynamicLoader",
    )
    expected_dynamic_loader = {
        "path": "/lib64/ld-linux-x86-64.so.2",
        "bytes": 236616,
        "sha256": (
            "1cd555ac46b7887edeaf3c42aac5408c8135e52f6b37870da2cf82d5fe14e829"
        ),
    }
    _require_exact_keys(
        dynamic_loader,
        set(expected_dynamic_loader),
        "captureEnvironment.dynamicLoader",
    )
    if dynamic_loader != expected_dynamic_loader:
        raise ProvenanceError("Verified recapture dynamic-loader pin differs.")
    libc = _object(
        environment["libc"],
        "captureEnvironment.libc",
    )
    expected_libc = {
        "path": "/lib/x86_64-linux-gnu/libc.so.6",
        "bytes": 2125328,
        "sha256": (
            "d8db8739a1633c972cec6a4fe0566bdcec6fd088f98723492ab0361f66238f75"
        ),
    }
    _require_exact_keys(
        libc,
        set(expected_libc),
        "captureEnvironment.libc",
    )
    if libc != expected_libc:
        raise ProvenanceError("Verified recapture libc pin differs.")
    if environment["networkPolicy"] != (
        "Network is used only for the verified producer artifacts and "
        "Semgrep dependency wheels. Rules and controlled fixture source are "
        "repository-local."
    ):
        raise ProvenanceError("Capture network policy differs.")

    expected_scripts = {
        "captureScript": "validation/tools/capture/capture-holdout.sh",
        "projectionScript": "validation/tools/capture/project_holdout.py",
        "projectionVerificationScript": (
            "validation/tools/capture/verify_projected_holdout.py"
        ),
        "sourceVerificationScript": (
            "validation/tools/capture/verify_source_transformations.py"
        ),
        "semgrepRunnerScript": "validation/tools/capture/run_semgrep.py",
        "semgrepCoreLoaderScript": (
            "validation/tools/capture/semgrep-core-loader.sh"
        ),
    }
    for field, expected_path in expected_scripts.items():
        if provenance[field] != expected_path:
            raise ProvenanceError(f"Capture provenance {field} path differs.")
        _regular_repository_file(
            repository_root,
            expected_path,
        )

    ordering = _object(
        provenance["gitleaksOrderingNormalization"],
        "gitleaksOrderingNormalization",
    )
    _require_exact_keys(
        ordering,
        {
            "script",
            "algorithmVersion",
            "invocation",
            "changedField",
            "reason",
            "committedProducerCaptureSha256",
            "normalizedProjectionInputSha256",
        },
        "gitleaksOrderingNormalization",
    )
    normalizer_path = (
        "validation/tools/capture/normalize_gitleaks_sarif.py"
    )
    if ordering["script"] != normalizer_path:
        raise ProvenanceError("Gitleaks ordering normalizer path differs.")
    _regular_repository_file(repository_root, normalizer_path)
    if ordering["algorithmVersion"] != ALGORITHM_VERSION:
        raise ProvenanceError("Gitleaks ordering algorithm version differs.")
    if ordering["invocation"] != (
        "python3 -B validation/tools/capture/normalize_gitleaks_sarif.py "
        "--input <producer-capture> --output "
        "<normalized-projection-input>"
    ):
        raise ProvenanceError("Gitleaks ordering normalizer invocation differs.")
    if ordering["changedField"] != "/runs/0/results":
        raise ProvenanceError("Gitleaks ordering changed-field declaration differs.")
    if ordering["reason"] != (
        "Gitleaks 8.30.1 appends findings produced by concurrent "
        "directory-fragment scans in completion order. The untouched "
        "producer bytes remain committed; only the complete result objects "
        "are sorted for a deterministic projection input."
    ):
        raise ProvenanceError("Gitleaks ordering rationale differs.")
    producer_hashes = _object(
        ordering["committedProducerCaptureSha256"],
        "committedProducerCaptureSha256",
    )
    normalized_hashes = _object(
        ordering["normalizedProjectionInputSha256"],
        "normalizedProjectionInputSha256",
    )
    _require_exact_keys(
        producer_hashes,
        {"baseline", "candidate"},
        "committedProducerCaptureSha256",
    )
    _require_exact_keys(
        normalized_hashes,
        {"baseline", "candidate"},
        "normalizedProjectionInputSha256",
    )
    for side in ("baseline", "candidate"):
        producer_capture = _regular_repository_file(
            repository_root,
            "validation/holdout/cases/gitleaks/producer-input/captures/"
            f"{side}.producer.sarif",
        )
        normalized_capture = _regular_repository_file(
            repository_root,
            "validation/holdout/cases/gitleaks/producer-input/captures/"
            f"{side}.raw.sarif",
        )
        if _sha256(producer_capture) != producer_hashes.get(side):
            raise ProvenanceError(
                f"Committed Gitleaks {side} producer capture hash differs."
            )
        if _sha256(normalized_capture) != normalized_hashes.get(side):
            raise ProvenanceError(
                f"Committed Gitleaks {side} normalized capture hash differs."
            )
    if provenance["reproductionCommand"] != (
        "./validation/tools/capture/capture-holdout.sh --output-root "
        "<new-staging-directory> --producer all"
    ):
        raise ProvenanceError("Capture reproduction command differs.")

    manifest_producers = {
        _string(item.get("id"), "manifest producer id"): item
        for item in (
            _object(raw, "manifest producer")
            for raw in _array(manifest.get("producers"), "manifest producers")
        )
    }
    provenance_producers = {
        _string(item.get("id"), "provenance producer id"): item
        for item in (
            _object(raw, "provenance producer")
            for raw in _array(provenance["producers"], "provenance producers")
        )
    }
    if (
        len(manifest_producers) != 3
        or len(provenance_producers) != 3
        or len(_array(manifest.get("producers"), "manifest producers")) != 3
        or len(_array(provenance["producers"], "provenance producers")) != 3
        or set(manifest_producers) != EXPECTED_PRODUCERS
        or set(provenance_producers) != EXPECTED_PRODUCERS
    ):
        raise ProvenanceError("Producer IDs must be exactly gitleaks, pmd, semgrep.")

    capture_date = _string(provenance["captureDate"], "captureDate")
    if capture_date != "2026-08-01":
        raise ProvenanceError("Capture date must remain 2026-08-01.")
    producer_key_sets = {
        "semgrep": {
            "id",
            "name",
            "version",
            "sourceCommit",
            "officialProject",
            "officialRelease",
            "license",
            "artifact",
            "dependencyLock",
            "nativeCore",
            "coreLoader",
            "executionMode",
            "versionCommand",
            "versionOutputSha256",
            "helpCommand",
            "helpSha256",
            "execution",
        },
        "gitleaks": {
            "id",
            "name",
            "version",
            "sourceCommit",
            "officialProject",
            "officialRelease",
            "license",
            "artifact",
            "officialChecksumManifest",
            "installation",
            "versionCommand",
            "helpCommand",
            "helpSha256",
            "versionOutputSha256",
            "execution",
        },
        "pmd": {
            "id",
            "name",
            "version",
            "sourceCommit",
            "officialProject",
            "officialRelease",
            "license",
            "artifact",
            "installation",
            "versionCommand",
            "helpCommand",
            "helpSha256",
            "execution",
        },
    }
    for producer_id in sorted(EXPECTED_PRODUCERS):
        declared = manifest_producers[producer_id]
        recorded = provenance_producers[producer_id]
        _require_exact_keys(
            recorded,
            producer_key_sets[producer_id],
            f"{producer_id} provenance",
        )
        expected_pairs = {
            "name": declared.get("displayName"),
            "version": declared.get("exactVersion"),
            "sourceCommit": declared.get("sourceCommit"),
            "officialProject": declared.get("projectUrl"),
            "officialRelease": declared.get("releaseUrl"),
            "license": _object(
                declared.get("license"),
                f"{producer_id} manifest license",
            ).get("spdxIdentifier"),
        }
        for field, expected in expected_pairs.items():
            if recorded.get(field) != expected:
                raise ProvenanceError(
                    f"{producer_id} provenance {field} differs from manifest."
                )
        expected_pin = EXPECTED_PINS[producer_id]
        for field in ("version", "sourceCommit"):
            if recorded.get(field) != expected_pin[field]:
                raise ProvenanceError(
                    f"{producer_id} {field} differs from the frozen pin."
                )
        for field, expected in EXPECTED_COMMAND_EVIDENCE[producer_id].items():
            if recorded.get(field) != expected:
                raise ProvenanceError(
                    f"{producer_id} {field} differs from captured evidence."
                )
        commit = _string(recorded["sourceCommit"], f"{producer_id} sourceCommit")
        if COMMIT_PATTERN.fullmatch(commit) is None:
            raise ProvenanceError(f"{producer_id} sourceCommit is not exact.")
        if declared.get("captureDate") != capture_date:
            raise ProvenanceError(
                f"{producer_id} capture date differs from provenance."
            )
        commands = _object(
            declared.get("commands"),
            f"{producer_id} manifest commands",
        )
        _require_exact_keys(
            commands,
            {"reproduction", "install", "capture"},
            f"{producer_id} manifest commands",
        )
        reproduction = _object(
            commands.get("reproduction"),
            f"{producer_id} reproduction command",
        )
        _require_exact_keys(
            reproduction,
            {"workingDirectory", "executable", "arguments", "environment"},
            f"{producer_id} reproduction command",
        )
        expected_reproduction = {
            "workingDirectory": "validation/tools/capture",
            "executable": "./capture-holdout.sh",
            "arguments": [
                "--output-root",
                "<new-staging-directory>",
                "--producer",
                producer_id,
            ],
            "environment": [],
        }
        if reproduction != expected_reproduction:
            raise ProvenanceError(
                f"{producer_id} authoritative reproduction command differs."
            )

        artifact = _object(recorded.get("artifact"), f"{producer_id} artifact")
        _require_exact_keys(
            artifact,
            {"kind", "url", "bytes", "sha256"},
            f"{producer_id} artifact",
        )
        artifact_tuple = (
            artifact.get("url"),
            artifact.get("sha256"),
            artifact.get("bytes"),
        )
        downloads = _array(
            declared.get("downloads"),
            f"{producer_id} manifest downloads",
        )
        download_tuples = {
            (
                _object(item, f"{producer_id} download").get("url"),
                _object(item, f"{producer_id} download").get("sha256"),
                _object(item, f"{producer_id} download").get("sizeBytes"),
            )
            for item in downloads
        }
        if artifact_tuple not in download_tuples:
            raise ProvenanceError(
                f"{producer_id} artifact does not match a manifest download."
            )
        if (
            artifact.get("sha256") != expected_pin["artifactSha256"]
            or artifact.get("bytes") != expected_pin["artifactBytes"]
        ):
            raise ProvenanceError(
                f"{producer_id} artifact differs from the frozen pin."
            )
        if SHA256_PATTERN.fullmatch(
            _string(artifact.get("sha256"), f"{producer_id} artifact sha256")
        ) is None:
            raise ProvenanceError(f"{producer_id} artifact SHA-256 is invalid.")

    semgrep_lock = _object(
        provenance_producers["semgrep"].get("dependencyLock"),
        "semgrep dependencyLock",
    )
    _require_exact_keys(
        semgrep_lock,
        {"path", "sha256", "pythonVersion", "installation"},
        "semgrep dependencyLock",
    )
    lock_path = _regular_repository_file(
        repository_root,
        _string(semgrep_lock.get("path"), "semgrep dependency lock path"),
    )
    expected_lock_sha = _string(
        semgrep_lock.get("sha256"),
        "semgrep dependency lock sha256",
    )
    if _sha256(lock_path) != expected_lock_sha:
        raise ProvenanceError("Semgrep dependency lock SHA-256 differs.")
    if semgrep_lock.get("path") != (
        "validation/tools/capture/"
        "semgrep-requirements.linux-x86_64-py312.lock"
    ):
        raise ProvenanceError("Semgrep dependency lock path differs.")
    if expected_lock_sha != (
        "456592933b886b3d60a68dfe83dba4af3f3e1872e492dbafcbbb388574e7039e"
    ):
        raise ProvenanceError("Semgrep dependency lock pin differs.")
    if semgrep_lock.get("pythonVersion") != "3.12":
        raise ProvenanceError("Semgrep dependency lock Python version differs.")
    if semgrep_lock.get("installation") != (
        "<temporary-tools>/semgrep-environment/bin/python -m pip install "
        "--no-index --find-links "
        "<temporary-wheelhouse> --only-binary=:all: --require-hashes "
        "--requirement validation/tools/capture/"
        "semgrep-requirements.linux-x86_64-py312.lock"
    ):
        raise ProvenanceError("Semgrep dependency installation command differs.")

    semgrep_native_core = _object(
        provenance_producers["semgrep"].get("nativeCore"),
        "semgrep nativeCore",
    )
    expected_native_core = {
        "installedPath": (
            "<temporary-tools>/semgrep-environment/lib/python3.12/"
            "site-packages/semgrep/bin/semgrep-core"
        ),
        "renamedPath": (
            "<temporary-tools>/semgrep-environment/lib/python3.12/"
            "site-packages/semgrep/bin/semgrep-core.native"
        ),
        "bytes": 253156344,
        "sha256": (
            "8a7c27e6286381fdb6235eb91bd0fed40b919496a242c72f1e55d2b5caa10cb2"
        ),
    }
    _require_exact_keys(
        semgrep_native_core,
        set(expected_native_core),
        "semgrep nativeCore",
    )
    if semgrep_native_core != expected_native_core:
        raise ProvenanceError("Semgrep native core evidence differs.")

    semgrep_core_loader = _object(
        provenance_producers["semgrep"].get("coreLoader"),
        "semgrep coreLoader",
    )
    expected_core_loader = {
        "sourcePath": "validation/tools/capture/semgrep-core-loader.sh",
        "installedPath": (
            "<temporary-tools>/semgrep-environment/lib/python3.12/"
            "site-packages/semgrep/bin/semgrep-core"
        ),
        "sha256": (
            "64930ae1e1bb0be1ca7b742c20c900f21a05352699d2852da141154077c68613"
        ),
        "dynamicLoader": "/lib64/ld-linux-x86-64.so.2",
        "invocation": (
            "/lib64/ld-linux-x86-64.so.2 --library-path "
            "<temporary-tools>/semgrep-environment/lib/python3.12/"
            "site-packages/semgrep/bin/libs --argv0 semgrep-core "
            "<temporary-tools>/semgrep-environment/lib/python3.12/"
            "site-packages/semgrep/bin/semgrep-core.native <core-arguments>"
        ),
    }
    _require_exact_keys(
        semgrep_core_loader,
        set(expected_core_loader),
        "semgrep coreLoader",
    )
    if semgrep_core_loader != expected_core_loader:
        raise ProvenanceError("Semgrep native core loader evidence differs.")
    loader_source = _regular_repository_file(
        repository_root,
        _string(semgrep_core_loader.get("sourcePath"), "core loader sourcePath"),
    )
    if _sha256(loader_source) != semgrep_core_loader["sha256"]:
        raise ProvenanceError("Semgrep core loader SHA-256 differs.")

    checksum_manifest = _object(
        provenance_producers["gitleaks"].get("officialChecksumManifest"),
        "gitleaks officialChecksumManifest",
    )
    _require_exact_keys(
        checksum_manifest,
        {"url", "bytes", "sha256"},
        "gitleaks officialChecksumManifest",
    )
    checksum_tuple = (
        checksum_manifest.get("url"),
        checksum_manifest.get("sha256"),
        checksum_manifest.get("bytes"),
    )
    gitleaks_downloads = {
        (
            _object(item, "gitleaks download").get("url"),
            _object(item, "gitleaks download").get("sha256"),
            _object(item, "gitleaks download").get("sizeBytes"),
        )
        for item in _array(
            manifest_producers["gitleaks"].get("downloads"),
            "gitleaks downloads",
        )
    }
    if checksum_tuple not in gitleaks_downloads:
        raise ProvenanceError(
            "Gitleaks checksum manifest differs from manifest downloads."
        )
    if checksum_tuple != (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/"
        "gitleaks_8.30.1_checksums.txt",
        "061476c21adaf5441516f96f185c1a4706a83cd6329b9b38762271b3d4a52fae",
        999,
    ):
        raise ProvenanceError("Gitleaks checksum manifest pin differs.")
    for producer_id in ("gitleaks", "pmd", "semgrep"):
        for field in ("helpSha256",):
            value = _string(
                provenance_producers[producer_id].get(field),
                f"{producer_id} {field}",
            )
            if SHA256_PATTERN.fullmatch(value) is None:
                raise ProvenanceError(f"{producer_id} {field} is invalid.")
    version_hash = _string(
        provenance_producers["gitleaks"].get("versionOutputSha256"),
        "gitleaks versionOutputSha256",
    )
    if SHA256_PATTERN.fullmatch(version_hash) is None:
        raise ProvenanceError("Gitleaks versionOutputSha256 is invalid.")
    semgrep_version_hash = _string(
        provenance_producers["semgrep"].get("versionOutputSha256"),
        "semgrep versionOutputSha256",
    )
    if SHA256_PATTERN.fullmatch(semgrep_version_hash) is None:
        raise ProvenanceError("Semgrep versionOutputSha256 is invalid.")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = _parser().parse_args(arguments)
    try:
        verify(parsed.repository_root)
    except (OSError, ProjectionError, ProvenanceError) as error:
        print(f"capture provenance verification failed: {error}", file=sys.stderr)
        return 1
    print("Verified pinned capture provenance and dependency hashes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
