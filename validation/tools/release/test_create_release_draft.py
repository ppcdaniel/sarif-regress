#!/usr/bin/env python3
"""Behavioral tests for the repository-owned GitHub release-draft client."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import urllib.parse

from create_release_draft import (
    ApiResponse,
    ReleaseAsset,
    ReleaseDraftError,
    RequestBody,
    _NoRedirectHandler,
    _decode_response,
    create_verified_release_draft,
    load_release_assets,
)


SOURCE_SHA = "a" * 40
TAG_OBJECT_SHA = "b" * 40
TAG = "v0.1.0-rc.1"
REPOSITORY = "ppcdaniel/sarif-regress"
API_ROOT = "https://api.github.com"


class FakeGitHubApi:
    """Implements the narrow deterministic API surface exercised by a draft."""

    def __init__(self, assets: tuple[ReleaseAsset, ...]) -> None:
        self.assets = {asset.name: asset for asset in assets}
        self.calls: list[tuple[str, str]] = []
        self.deleted = False
        self.existing_release = False
        self.tag_commit = SOURCE_SHA
        self.upload_host = "uploads.github.com"
        self.incorrect_upload_digest = False
        self.omit_final_asset = False
        self.created = False
        self.malformed_creation_response = False
        self.concurrent_creation_failure = False
        self.release_name = f"SarifRegress {TAG}"

    def __call__(
            self, method: str, url: str, body: RequestBody | None,
            allowed_statuses: frozenset[int]) -> ApiResponse:
        self.calls.append((method, url))
        path = urllib.parse.urlsplit(url).path
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)

        if method == "GET" and path.endswith(f"/releases/tags/{TAG}"):
            if self.existing_release:
                return self._respond(200, {"id": 9}, allowed_statuses)
            if self.created:
                return self._respond(200, self._release_document([]), allowed_statuses)
            return self._respond(404, None, allowed_statuses)
        if method == "GET" and path.endswith(f"/git/ref/tags/{TAG}"):
            return self._respond(
                200, {"object": {"type": "tag", "sha": TAG_OBJECT_SHA}}, allowed_statuses)
        if method == "GET" and path.endswith(f"/git/tags/{TAG_OBJECT_SHA}"):
            return self._respond(
                200, {"object": {"type": "commit", "sha": self.tag_commit}}, allowed_statuses)
        if method == "POST" and path.endswith("/releases"):
            if self.concurrent_creation_failure:
                self.created = True
                raise ReleaseDraftError("simulated HTTP 422")
            assert body is not None and body.json_bytes is not None
            request_document = json.loads(body.json_bytes)
            self._created_request = request_document
            self.created = True
            document = {"id": "invalid"} if self.malformed_creation_response else self._release_document([])
            return self._respond(201, document, allowed_statuses)
        if method == "POST" and path.endswith("/releases/17/assets"):
            assert body is not None and body.asset_path is not None
            name = query["name"][0]
            asset = self.assets[name]
            digest = "0" * 64 if self.incorrect_upload_digest else asset.sha256
            return self._respond(
                201,
                {
                    "name": name,
                    "state": "uploaded",
                    "size": asset.length,
                    "digest": f"sha256:{digest}",
                },
                allowed_statuses,
            )
        if method == "GET" and path.endswith("/releases/17"):
            assets = list(self.assets.values())
            if self.omit_final_asset:
                assets = assets[:-1]
            document = self._release_document(
                [
                    {
                        "name": asset.name,
                        "state": "uploaded",
                        "size": asset.length,
                        "digest": f"sha256:{asset.sha256}",
                    }
                    for asset in assets
                ])
            return self._respond(
                200,
                document,
                allowed_statuses,
            )
        if method == "DELETE" and path.endswith("/releases/17"):
            self.deleted = True
            return self._respond(204, None, allowed_statuses)
        raise AssertionError(f"Unexpected fake request: {method} {url}")

    @staticmethod
    def _respond(
            status: int, document: dict[str, object] | None,
            allowed_statuses: frozenset[int]) -> ApiResponse:
        if status not in allowed_statuses:
            raise ReleaseDraftError(f"simulated HTTP {status}")
        return ApiResponse(status, document)

    def _release_document(self, assets: list[dict[str, object]]) -> dict[str, object]:
        return {
            "id": 17,
            "tag_name": TAG,
            "target_commitish": SOURCE_SHA,
            "draft": True,
            "prerelease": True,
            "name": self.release_name,
            "body": "Release notes.\n",
            "upload_url":
                f"https://{self.upload_host}/repos/{REPOSITORY}/releases/17/assets{{?name,label}}",
            "assets": assets,
        }


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self._write_valid_bundle()

    def _write_valid_bundle(self) -> None:
        from create_release_draft import _expected_asset_names

        names = _expected_asset_names(TAG)
        for name in names - {"checksums.sha256"}:
            payload = (SOURCE_SHA + "\n").encode("ascii") if name == "source-commit.txt" else (
                f"verified release payload: {name}\n".encode("utf-8"))
            (self.root / name).write_bytes(payload)
        manifest = "".join(
            f"{hashlib.sha256((self.root / name).read_bytes()).hexdigest()}  {name}\n"
            for name in sorted(names - {"checksums.sha256"})
        )
        (self.root / "checksums.sha256").write_text(
            manifest, encoding="ascii", newline="\n")

    def test_exact_bundle_is_loaded_in_ordinal_order(self) -> None:
        assets = load_release_assets(self.root, TAG, SOURCE_SHA)

        self.assertEqual([asset.name for asset in assets], sorted(asset.name for asset in assets))
        self.assertEqual(len(assets), 15)

    def test_unexpected_asset_is_refused(self) -> None:
        (self.root / "surprise.txt").write_text("unexpected\n", encoding="utf-8")

        with self.assertRaisesRegex(ReleaseDraftError, "asset set is not exact"):
            load_release_assets(self.root, TAG, SOURCE_SHA)

    def test_tampered_asset_is_refused(self) -> None:
        (self.root / "corpus-report.json").write_text("tampered\n", encoding="utf-8")

        with self.assertRaisesRegex(ReleaseDraftError, "does not match checksums"):
            load_release_assets(self.root, TAG, SOURCE_SHA)

    def test_wrong_source_commit_is_refused(self) -> None:
        with self.assertRaisesRegex(ReleaseDraftError, "source-commit"):
            load_release_assets(self.root, TAG, "c" * 40)


class ReleaseTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        path = Path(self.temporary.name) / "asset.bin"
        path.write_bytes(b"release asset\n")
        self.asset = ReleaseAsset(
            "asset.bin", path, path.stat().st_size, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assets = (self.asset,)
        self.api = FakeGitHubApi(self.assets)

    def _create(self) -> int:
        return create_verified_release_draft(
            self.api,
            API_ROOT,
            REPOSITORY,
            TAG,
            SOURCE_SHA,
            "Release notes.\n",
            self.assets,
        )

    def test_annotated_tag_draft_is_uploaded_and_read_back(self) -> None:
        release_id = self._create()

        self.assertEqual(release_id, 17)
        self.assertFalse(self.api.deleted)
        self.assertEqual(self.api._created_request["tag_name"], TAG)
        self.assertTrue(self.api._created_request["draft"])
        self.assertTrue(self.api._created_request["prerelease"])
        self.assertFalse(self.api._created_request["generate_release_notes"])
        self.assertEqual(self.api._created_request["make_latest"], "false")

    def test_existing_release_is_refused_before_creation(self) -> None:
        self.api.existing_release = True

        with self.assertRaisesRegex(ReleaseDraftError, "already exists"):
            self._create()

        self.assertFalse(any(method == "POST" for method, _ in self.api.calls))

    def test_tag_commit_mismatch_is_refused_before_creation(self) -> None:
        self.api.tag_commit = "c" * 40

        with self.assertRaisesRegex(ReleaseDraftError, "different commits"):
            self._create()

        self.assertFalse(any(method == "POST" for method, _ in self.api.calls))

    def test_incorrect_uploaded_digest_retains_partial_draft(self) -> None:
        self.api.incorrect_upload_digest = True

        with self.assertRaisesRegex(
                ReleaseDraftError,
                "incorrect digest.*partial draft 17 was retained"):
            self._create()

        self.assertFalse(self.api.deleted)
        self.assertFalse(any(method == "DELETE" for method, _ in self.api.calls))

    def test_malformed_creation_response_does_not_delete_unattributed_draft(self) -> None:
        self.api.malformed_creation_response = True

        with self.assertRaisesRegex(ReleaseDraftError, "invalid ID"):
            self._create()

        self.assertFalse(self.api.deleted)

    def test_concurrent_release_is_not_deleted_after_creation_failure(self) -> None:
        self.api.concurrent_creation_failure = True

        with self.assertRaisesRegex(ReleaseDraftError, "simulated HTTP 422"):
            self._create()

        self.assertFalse(self.api.deleted)

    def test_untrusted_upload_host_retains_partial_draft(self) -> None:
        self.api.upload_host = "example.invalid"

        with self.assertRaisesRegex(
                ReleaseDraftError,
                "outside the authenticated API host.*partial draft 17 was retained"):
            self._create()

        self.assertFalse(self.api.deleted)

    def test_incomplete_final_asset_set_retains_partial_draft(self) -> None:
        self.api.omit_final_asset = True

        with self.assertRaisesRegex(
                ReleaseDraftError,
                "exact asset count.*partial draft 17 was retained"):
            self._create()

        self.assertFalse(self.api.deleted)

    def test_incorrect_release_title_retains_partial_draft(self) -> None:
        self.api.release_name = "Unexpected title"

        with self.assertRaisesRegex(
                ReleaseDraftError,
                "incorrect title.*partial draft 17 was retained"):
            self._create()

        self.assertFalse(self.api.deleted)
        self.assertFalse(any(method == "DELETE" for method, _ in self.api.calls))

    def test_untrusted_api_origin_is_refused_before_any_request(self) -> None:
        with self.assertRaisesRegex(
                ReleaseDraftError,
                "must be https://api.github.com"):
            create_verified_release_draft(
                self.api,
                "https://example.invalid",
                REPOSITORY,
                TAG,
                SOURCE_SHA,
                "Release notes.\n",
                self.assets,
            )

        self.assertEqual([], self.api.calls)

    def test_api_origin_with_credentials_or_port_is_refused(self) -> None:
        for api_root in (
                "https://token@api.github.com",
                "https://api.github.com:443",
                "https://api.github.com/repos",
                "https://api.github.com?redirect=example.invalid"):
            with self.subTest(api_root=api_root):
                with self.assertRaisesRegex(
                        ReleaseDraftError,
                        "must be https://api.github.com"):
                    create_verified_release_draft(
                        self.api,
                        api_root,
                        REPOSITORY,
                        TAG,
                        SOURCE_SHA,
                        "Release notes.\n",
                        self.assets,
                    )

        self.assertEqual([], self.api.calls)

    def test_duplicate_api_json_key_is_refused(self) -> None:
        with self.assertRaisesRegex(ReleaseDraftError, "duplicate JSON key"):
            _decode_response(b'{"id":1,"id":2}', "test response")

    def test_redirect_handler_refuses_token_and_body_replay(self) -> None:
        original = urllib.request.Request(
            "https://api.github.com/source",
            data=b"asset",
            headers={"Authorization": "Bearer secret"},
            method="POST",
        )

        redirected = _NoRedirectHandler().redirect_request(
            original,
            None,
            307,
            "Temporary Redirect",
            {},
            "https://example.invalid/collect",
        )

        self.assertIsNone(redirected)


if __name__ == "__main__":
    unittest.main()
