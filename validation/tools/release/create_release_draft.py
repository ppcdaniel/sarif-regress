#!/usr/bin/env python3
"""Create one exact-tag GitHub release draft from a verified asset bundle."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable, Iterable, Mapping
import urllib.error
import urllib.parse
import urllib.request

from verify_release_gate import COMMIT_PATTERN, SEMVER_TAG_PATTERN, SHA256_PATTERN


API_VERSION = "2022-11-28"
GITHUB_API_ROOT = "https://api.github.com"
MAX_API_RESPONSE_BYTES = 1024 * 1024
MAX_NOTES_BYTES = 256 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 64 * 1024
MAX_TAG_INDIRECTION = 8
REPOSITORY_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")
ASSET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")

FIXED_RELEASE_ASSET_NAMES = frozenset(
    {
        "DOTNET_RUNTIME_LICENSE.txt",
        "DOTNET_RUNTIME_THIRD_PARTY_NOTICES.txt",
        "LICENSE",
        "SYSTEM_COMMANDLINE_LICENSE.md",
        "THIRD_PARTY_NOTICES.md",
        "benchmark-pathological-deterministic.json",
        "benchmark-pathological.json",
        "benchmark-unique-deterministic.json",
        "benchmark-unique.json",
        "checksums.sha256",
        "corpus-report.json",
        "sarif-regress-linux-x64",
        "sarif-regress-win-x64.exe",
        "source-commit.txt",
    }
)


class ReleaseDraftError(RuntimeError):
    """Reports a deterministic release-draft refusal without exposing credentials."""


@dataclass(frozen=True)
class RequestBody:
    """Describes either bounded JSON bytes or one streamed release asset."""

    content_type: str
    length: int
    json_bytes: bytes | None = None
    asset_path: Path | None = None


@dataclass(frozen=True)
class ApiResponse:
    """Contains one bounded HTTP response."""

    status: int
    document: Mapping[str, Any] | None


@dataclass(frozen=True)
class ReleaseAsset:
    """Binds one regular release file to its size and SHA-256 digest."""

    name: str
    path: Path
    length: int
    sha256: str


RequestFunction = Callable[[str, str, RequestBody | None, frozenset[int]], ApiResponse]


def _is_link_like(path: Path) -> bool:
    """Return whether a path is a symbolic link or Windows junction."""

    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _require_physical_regular_file(path: Path, label: str, maximum_bytes: int) -> int:
    """Validate a file and every existing path component without following links."""

    absolute_path = path.absolute()
    for component in reversed((absolute_path, *absolute_path.parents)):
        if not component.exists() and not _is_link_like(component):
            continue
        if _is_link_like(component):
            raise ReleaseDraftError(f"{label} traverses a link or junction.")

    try:
        metadata = absolute_path.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseDraftError(f"{label} cannot be inspected: {error}.") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ReleaseDraftError(f"{label} must be a regular file.")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise ReleaseDraftError(
            f"{label} must contain between 1 and {maximum_bytes} bytes.")
    return metadata.st_size


# Time: O(n). Space: O(1), excluding the fixed hash state.
def _hash_file(path: Path) -> str:
    """Hash a release file through a bounded-memory streaming read."""

    digest = hashlib.sha256()
    try:
        with path.open("rb", buffering=0) as stream:
            while chunk := stream.read(UPLOAD_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as error:
        raise ReleaseDraftError(f"Release asset {path.name} cannot be read: {error}.") from error
    return digest.hexdigest()


def _expected_asset_names(tag: str) -> frozenset[str]:
    """Return the exact release-asset allowlist for a semantic-version tag."""

    if SEMVER_TAG_PATTERN.fullmatch(tag) is None:
        raise ReleaseDraftError("The release tag is not a canonical semantic-version tag.")
    return FIXED_RELEASE_ASSET_NAMES | {f"SarifRegress.Tool.{tag[1:]}.nupkg"}


def _read_checksum_manifest(path: Path) -> dict[str, str]:
    """Read a strict, ordinally sorted release checksum manifest."""

    length = _require_physical_regular_file(
        path, "The release checksum manifest", MAX_NOTES_BYTES)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ReleaseDraftError(f"The release checksum manifest cannot be read: {error}.") from error
    if len(payload) != length or not payload.endswith(b"\n") or b"\r" in payload:
        raise ReleaseDraftError("The release checksum manifest is not canonical LF text.")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReleaseDraftError("The release checksum manifest must be ASCII.") from error

    entries: dict[str, str] = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+-]{0,127})", line)
        if match is None:
            raise ReleaseDraftError("The release checksum manifest has an invalid entry.")
        digest, name = match.groups()
        if name in entries:
            raise ReleaseDraftError("The release checksum manifest contains a duplicate name.")
        entries[name] = digest
    if list(entries) != sorted(entries):
        raise ReleaseDraftError("The release checksum manifest is not ordinally sorted.")
    return entries


# Time: O(a * n), where a is the fixed 15-file allowlist. Space: O(a).
def load_release_assets(asset_root: Path, tag: str, expected_commit: str) -> tuple[ReleaseAsset, ...]:
    """Authenticate the exact allowlisted asset set and its checksum graph."""

    if COMMIT_PATTERN.fullmatch(expected_commit) is None:
        raise ReleaseDraftError("The expected source commit is not a full SHA-1 object ID.")
    root = asset_root.absolute()
    if _is_link_like(root):
        raise ReleaseDraftError("The release asset root must not be a link or junction.")
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except OSError as error:
        raise ReleaseDraftError(f"The release asset root cannot be inspected: {error}.") from error
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ReleaseDraftError("The release asset root must be a directory.")

    expected_names = _expected_asset_names(tag)
    try:
        actual_entries = tuple(root.iterdir())
    except OSError as error:
        raise ReleaseDraftError(f"The release asset root cannot be enumerated: {error}.") from error
    actual_names = {entry.name for entry in actual_entries}
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        unexpected = sorted(actual_names - expected_names)
        raise ReleaseDraftError(
            f"The release asset set is not exact; missing={missing}, unexpected={unexpected}.")

    checksums = _read_checksum_manifest(root / "checksums.sha256")
    expected_hashed_names = expected_names - {"checksums.sha256"}
    if set(checksums) != expected_hashed_names:
        raise ReleaseDraftError("The release checksum manifest does not bind the exact asset set.")

    assets: list[ReleaseAsset] = []
    for name in sorted(expected_names):
        if ASSET_NAME_PATTERN.fullmatch(name) is None:
            raise ReleaseDraftError("A release asset name is not portable.")
        path = root / name
        length = _require_physical_regular_file(path, f"Release asset {name}", MAX_ASSET_BYTES)
        digest = _hash_file(path)
        if name != "checksums.sha256" and checksums[name] != digest:
            raise ReleaseDraftError(f"Release asset {name} does not match checksums.sha256.")
        assets.append(ReleaseAsset(name, path, length, digest))

    source_commit = (root / "source-commit.txt").read_bytes()
    if source_commit != (expected_commit + "\n").encode("ascii"):
        raise ReleaseDraftError("source-commit.txt does not bind the expected source commit.")
    return tuple(assets)


def _require_object(response: ApiResponse, context: str) -> Mapping[str, Any]:
    """Require one JSON object response."""

    if response.document is None:
        raise ReleaseDraftError(f"{context} did not return a JSON object.")
    return response.document


def _require_object_pointer(document: Mapping[str, Any], context: str) -> tuple[str, str]:
    """Read one Git object pointer from a bounded API response."""

    pointer = document.get("object")
    if not isinstance(pointer, dict):
        raise ReleaseDraftError(f"{context} omitted its Git object pointer.")
    object_type = pointer.get("type")
    object_sha = pointer.get("sha")
    if object_type not in {"commit", "tag"} or not isinstance(object_sha, str):
        raise ReleaseDraftError(f"{context} returned an invalid Git object pointer.")
    if COMMIT_PATTERN.fullmatch(object_sha) is None:
        raise ReleaseDraftError(f"{context} returned an invalid Git object ID.")
    return object_type, object_sha


# Time: O(d), where d <= MAX_TAG_INDIRECTION. Space: O(1).
def resolve_tag_commit(request: RequestFunction, api_root: str, repository: str, tag: str) -> str:
    """Resolve a lightweight or annotated tag to exactly one commit."""

    encoded_tag = urllib.parse.quote(tag, safe="")
    response = request(
        "GET", f"{api_root}/repos/{repository}/git/ref/tags/{encoded_tag}", None, frozenset({200}))
    object_type, object_sha = _require_object_pointer(
        _require_object(response, "The release tag reference"), "The release tag reference")
    for _ in range(MAX_TAG_INDIRECTION):
        if object_type == "commit":
            return object_sha
        response = request(
            "GET", f"{api_root}/repos/{repository}/git/tags/{object_sha}", None, frozenset({200}))
        object_type, object_sha = _require_object_pointer(
            _require_object(response, "An annotated tag"), "An annotated tag")
    raise ReleaseDraftError("The release tag exceeds the bounded annotated-tag depth.")


def _json_body(document: Mapping[str, Any]) -> RequestBody:
    """Encode one compact deterministic JSON request body."""

    payload = json.dumps(
        document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("ascii")
    return RequestBody("application/json", len(payload), json_bytes=payload)


def _asset_body(asset: ReleaseAsset) -> RequestBody:
    """Create a streamed request descriptor for one asset."""

    return RequestBody("application/octet-stream", asset.length, asset_path=asset.path)


def _validate_created_release(
        document: Mapping[str, Any], tag: str, prerelease: bool) -> tuple[int, str]:
    """Validate the security-sensitive fields returned for a new draft."""

    release_id = document.get("id")
    upload_url = document.get("upload_url")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id <= 0:
        raise ReleaseDraftError("The created release has an invalid ID.")
    if document.get("tag_name") != tag:
        raise ReleaseDraftError("The created release does not bind the requested tag.")
    if document.get("name") != f"SarifRegress {tag}":
        raise ReleaseDraftError("The created release has an incorrect title.")
    if document.get("draft") is not True or document.get("prerelease") is not prerelease:
        raise ReleaseDraftError("The created release has incorrect publication flags.")
    if not isinstance(upload_url, str) or not upload_url.endswith("{?name,label}"):
        raise ReleaseDraftError("The created release omitted its canonical upload URL.")
    return release_id, upload_url.removesuffix("{?name,label}")


def _validate_uploaded_asset(document: Mapping[str, Any], asset: ReleaseAsset) -> None:
    """Require GitHub to attest the exact uploaded asset name, size, state, and digest."""

    if document.get("name") != asset.name or document.get("state") != "uploaded":
        raise ReleaseDraftError(f"GitHub did not finalize release asset {asset.name}.")
    if document.get("size") != asset.length:
        raise ReleaseDraftError(f"GitHub reported an incorrect size for release asset {asset.name}.")
    if document.get("digest") != f"sha256:{asset.sha256}":
        raise ReleaseDraftError(f"GitHub reported an incorrect digest for release asset {asset.name}.")


def _validate_final_release(
        document: Mapping[str, Any], release_id: int, tag: str,
        prerelease: bool, notes: str, assets: tuple[ReleaseAsset, ...]) -> None:
    """Read back the complete draft and require the exact uploaded asset set."""

    confirmed_id, _ = _validate_created_release(
        document, tag, prerelease)
    if confirmed_id != release_id or document.get("body") != notes:
        raise ReleaseDraftError("The completed release draft changed identity or release notes.")
    uploaded_assets = document.get("assets")
    if not isinstance(uploaded_assets, list) or len(uploaded_assets) != len(assets):
        raise ReleaseDraftError("The completed release draft does not contain the exact asset count.")
    by_name: dict[str, Mapping[str, Any]] = {}
    for uploaded in uploaded_assets:
        if not isinstance(uploaded, dict) or not isinstance(uploaded.get("name"), str):
            raise ReleaseDraftError("The completed release draft contains invalid asset metadata.")
        name = uploaded["name"]
        if name in by_name:
            raise ReleaseDraftError("The completed release draft contains a duplicate asset name.")
        by_name[name] = uploaded
    if set(by_name) != {asset.name for asset in assets}:
        raise ReleaseDraftError("The completed release draft contains an unexpected asset set.")
    for asset in assets:
        _validate_uploaded_asset(by_name[asset.name], asset)


def _normalize_api_root(api_root: str) -> str:
    """Require GitHub.com's canonical API origin before sending credentials."""

    try:
        parsed = urllib.parse.urlsplit(api_root)
        port = parsed.port
    except ValueError as error:
        raise ReleaseDraftError("The GitHub API root is invalid.") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != "api.github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ReleaseDraftError(
            f"The GitHub API root must be {GITHUB_API_ROOT}.")
    return GITHUB_API_ROOT


# Time: O(a * n), where a is fixed and n is total asset bytes. Space: O(a).
def create_verified_release_draft(
        request: RequestFunction,
        api_root: str,
        repository: str,
        tag: str,
        expected_commit: str,
        notes: str,
        assets: tuple[ReleaseAsset, ...]) -> int:
    """Create, populate, and authenticate a draft without automatic deletion."""

    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ReleaseDraftError("The GitHub repository identifier is invalid.")
    if COMMIT_PATTERN.fullmatch(expected_commit) is None:
        raise ReleaseDraftError("The expected source commit is invalid.")
    tag_match = SEMVER_TAG_PATTERN.fullmatch(tag)
    if tag_match is None:
        raise ReleaseDraftError("The release tag is invalid.")
    if len(notes.encode("utf-8")) > MAX_NOTES_BYTES:
        raise ReleaseDraftError("The release notes exceed the bounded input size.")
    api_root = _normalize_api_root(api_root)

    encoded_tag = urllib.parse.quote(tag, safe="")
    existing = request(
        "GET", f"{api_root}/repos/{repository}/releases/tags/{encoded_tag}", None,
        frozenset({200, 404}))
    if existing.status != 404:
        raise ReleaseDraftError(f"Release {tag} already exists; refusing to overwrite it.")
    if resolve_tag_commit(request, api_root, repository, tag) != expected_commit:
        raise ReleaseDraftError("The release tag and source bundle resolve to different commits.")

    prerelease = tag_match.group("prerelease") is not None
    release_id: int | None = None
    try:
        response = request(
            "POST",
            f"{api_root}/repos/{repository}/releases",
            _json_body(
                {
                    "body": notes,
                    "draft": True,
                    "generate_release_notes": False,
                    "make_latest": "false" if prerelease else "true",
                    "name": f"SarifRegress {tag}",
                    "prerelease": prerelease,
                    "tag_name": tag,
                    "target_commitish": expected_commit,
                }),
            frozenset({201}))
        release_document = _require_object(response, "Release creation")
        untrusted_release_id = release_document.get("id")
        if (isinstance(untrusted_release_id, int) and not isinstance(
                untrusted_release_id, bool) and untrusted_release_id > 0):
            release_id = untrusted_release_id
        release_id, upload_url = _validate_created_release(
            release_document, tag, prerelease)
        expected_upload_path = f"/repos/{repository}/releases/{release_id}/assets"
        parsed_upload = urllib.parse.urlsplit(upload_url)
        parsed_api = urllib.parse.urlsplit(api_root)
        if parsed_upload.scheme != "https" or parsed_upload.username or parsed_upload.password:
            raise ReleaseDraftError("The release upload URL is not a safe HTTPS endpoint.")
        allowed_upload_hosts = {parsed_api.hostname}
        if parsed_api.hostname == "api.github.com":
            allowed_upload_hosts.add("uploads.github.com")
        if parsed_upload.hostname not in allowed_upload_hosts:
            raise ReleaseDraftError("The release upload URL is outside the authenticated API host.")
        expected_upload_port = None if parsed_upload.hostname == "uploads.github.com" else parsed_api.port
        if parsed_upload.port != expected_upload_port:
            raise ReleaseDraftError("The release upload URL changed the authenticated API port.")
        if parsed_upload.path != expected_upload_path or parsed_upload.query or parsed_upload.fragment:
            raise ReleaseDraftError("The release upload URL does not bind this repository and release.")

        for asset in assets:
            encoded_name = urllib.parse.urlencode({"name": asset.name})
            uploaded = request(
                "POST", f"{upload_url}?{encoded_name}", _asset_body(asset), frozenset({201}))
            _validate_uploaded_asset(
                _require_object(uploaded, f"Upload of release asset {asset.name}"), asset)
        completed = request(
            "GET", f"{api_root}/repos/{repository}/releases/{release_id}", None,
            frozenset({200}))
        _validate_final_release(
            _require_object(completed, "Completed release draft"),
            release_id,
            tag,
            prerelease,
            notes,
            assets,
        )
        if resolve_tag_commit(request, api_root, repository, tag) != expected_commit:
            raise ReleaseDraftError("The release tag changed during draft creation.")
    except Exception as primary_error:
        if release_id is not None:
            raise ReleaseDraftError(
                "Release draft creation failed "
                f"({primary_error}); partial draft {release_id} was retained "
                "for explicit owner review.") \
                from primary_error
        if isinstance(primary_error, ReleaseDraftError):
            raise
        raise ReleaseDraftError(f"Release draft creation failed: {primary_error}.") from primary_error
    if release_id is None:
        raise ReleaseDraftError("Release creation completed without an authenticated release ID.")
    return release_id


class _FileChunks:
    """Yield a regular file in fixed-size chunks without retaining it in memory."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def __iter__(self) -> Iterable[bytes]:
        with self._path.open("rb", buffering=0) as stream:
            while chunk := stream.read(UPLOAD_CHUNK_BYTES):
                yield chunk


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so authorization and upload bodies are never replayed."""

    def redirect_request(
            self, request: urllib.request.Request, file_pointer: Any,
            code: int, message: str, headers: Mapping[str, str],
            new_url: str) -> urllib.request.Request | None:
        return None


def _decode_response(payload: bytes, context: str) -> Mapping[str, Any] | None:
    """Decode one bounded duplicate-key-free API JSON object."""

    if not payload:
        return None

    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseDraftError(f"{context} contains a duplicate JSON key.")
            result[key] = value
        return result

    try:
        document = json.loads(
            payload.decode("utf-8"), object_pairs_hook=reject_duplicate,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ReleaseDraftError(f"{context} contains non-finite JSON.")))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReleaseDraftError(f"{context} is not strict UTF-8 JSON.") from error
    if not isinstance(document, dict):
        raise ReleaseDraftError(f"{context} must be a JSON object.")
    return document


def build_urllib_request(token: str) -> RequestFunction:
    """Create the production HTTPS transport with bounded response reads."""

    if not token or "\r" in token or "\n" in token:
        raise ReleaseDraftError("GITHUB_TOKEN is missing or invalid.")
    opener = urllib.request.build_opener(_NoRedirectHandler())

    def send(
            method: str, url: str, body: RequestBody | None,
            allowed_statuses: frozenset[int]) -> ApiResponse:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "sarif-regress-release-gate",
            "X-GitHub-Api-Version": API_VERSION,
        }
        data: bytes | Iterable[bytes] | None = None
        if body is not None:
            headers["Content-Type"] = body.content_type
            headers["Content-Length"] = str(body.length)
            data = body.json_bytes if body.json_bytes is not None else _FileChunks(body.asset_path)  # type: ignore[arg-type]
        api_request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            response = opener.open(api_request, timeout=60)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError) as error:
            raise ReleaseDraftError(f"GitHub API request failed: {type(error).__name__}.") from error
        with response:
            status = response.status
            payload = response.read(MAX_API_RESPONSE_BYTES + 1)
        if len(payload) > MAX_API_RESPONSE_BYTES:
            raise ReleaseDraftError("A GitHub API response exceeded the bounded size.")
        if status not in allowed_statuses:
            raise ReleaseDraftError(f"GitHub API request failed with HTTP {status}.")
        document = _decode_response(payload, "A GitHub API response")
        return ApiResponse(status, document)

    return send


def _read_notes(path: Path) -> str:
    """Read canonical bounded UTF-8 release notes from a regular file."""

    length = _require_physical_regular_file(path, "The release notes", MAX_NOTES_BYTES)
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ReleaseDraftError(f"The release notes cannot be read: {error}.") from error
    if len(payload) != length or not payload.endswith(b"\n") or b"\r" in payload:
        raise ReleaseDraftError("The release notes must be canonical LF text with a final line feed.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ReleaseDraftError("The release notes must be valid UTF-8.") from error


def _parse_arguments() -> argparse.Namespace:
    """Parse the narrow release-draft command contract."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--asset-root", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    """Run the authenticated release-draft transaction."""

    arguments = _parse_arguments()
    try:
        assets = load_release_assets(
            arguments.asset_root, arguments.tag, arguments.expected_commit)
        notes = _read_notes(arguments.notes)
        request = build_urllib_request(os.environ.get("GITHUB_TOKEN", ""))
        release_id = create_verified_release_draft(
            request,
            arguments.api_url,
            arguments.repository,
            arguments.tag,
            arguments.expected_commit,
            notes,
            assets,
        )
    except ReleaseDraftError as error:
        print(f"Release draft refused: {error}", file=sys.stderr)
        return 1
    print(f"Created verified GitHub release draft {release_id}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
