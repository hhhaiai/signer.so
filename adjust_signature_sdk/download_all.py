#!/usr/bin/env python3
"""Discover and download every Adjust Signature SDK release asset.

The script uses only the Python standard library. Assets are stored below the
directory containing this file, grouped by GitHub release tag. Re-running the
script skips complete files and resumes only downloads left in ``.part`` files.
"""

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_URL = "https://api.github.com/repos/adjust/adjust_signature_sdk/releases?per_page=100"
USER_AGENT = "adjust-signature-sdk-downloader/1.0"
CHUNK_SIZE = 1024 * 1024
DEFAULT_TIMEOUT = 30
DEFAULT_RETRIES = 4
SHA256_RE = re.compile(r"^sha256:([0-9a-fA-F]{64})$")


class MetadataError(Exception):
    """GitHub returned release metadata that is unsafe or malformed."""


class DownloadError(Exception):
    """An asset could not be downloaded and verified."""


@dataclass(frozen=True)
class Asset:
    tag: str
    name: str
    size: int
    url: str
    digest: str = ""


def _headers(token: Optional[str] = None) -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = "Bearer {}".format(token)
    return headers


def _next_link(link_header: Optional[str]) -> Optional[str]:
    if not link_header:
        return None
    for item in link_header.split(","):
        match = re.match(r'\s*<([^>]+)>\s*;\s*rel="([^"]+)"', item)
        if match and match.group(2) == "next":
            return match.group(1)
    return None


def _validate_asset(tag: object, raw: object) -> Asset:
    if not isinstance(tag, str) or not isinstance(raw, dict):
        raise MetadataError("release tag or asset entry has an invalid type")

    name = raw.get("name")
    size = raw.get("size")
    url = raw.get("browser_download_url")
    digest = raw.get("digest") or ""

    if not isinstance(name, str) or not name:
        raise MetadataError("asset name is missing or invalid")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise MetadataError("asset size is missing or invalid for {}".format(name))
    if not isinstance(url, str) or not url.startswith(("https://", "http://")):
        raise MetadataError("asset URL is missing or invalid for {}".format(name))
    if not isinstance(digest, str):
        raise MetadataError("asset digest has an invalid type for {}".format(name))
    if digest and not SHA256_RE.match(digest):
        raise MetadataError("unsupported asset digest for {}: {}".format(name, digest))

    return Asset(tag=tag, name=name, size=size, url=url, digest=digest)


def fetch_releases(
    api_url: str = API_URL,
    token: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    opener: Callable = urlopen,
) -> Tuple[int, List[Asset]]:
    """Fetch every page of GitHub release metadata."""

    releases = 0
    assets = []
    next_url = api_url
    visited = set()

    while next_url:
        if next_url in visited:
            raise MetadataError("GitHub pagination contains a loop")
        visited.add(next_url)

        request = Request(next_url, headers=_headers(token))
        try:
            with opener(request, timeout=timeout) as response:
                body = response.read()
                link_header = response.headers.get("Link")
        except (HTTPError, URLError, OSError) as error:
            raise MetadataError("failed to fetch releases: {}".format(error)) from error

        try:
            page = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise MetadataError("GitHub releases response is not valid JSON") from error
        if not isinstance(page, list):
            raise MetadataError("GitHub releases response is not a list")

        for release in page:
            if not isinstance(release, dict):
                raise MetadataError("release entry has an invalid type")
            if release.get("draft") is True:
                continue
            tag = release.get("tag_name")
            raw_assets = release.get("assets")
            if not isinstance(tag, str) or not tag:
                raise MetadataError("release tag is missing or invalid")
            if not isinstance(raw_assets, list):
                raise MetadataError("asset list is missing or invalid for {}".format(tag))
            releases += 1
            for raw_asset in raw_assets:
                assets.append(_validate_asset(tag, raw_asset))

        next_url = _next_link(link_header)

    return releases, assets


def _safe_component(value: str, label: str) -> None:
    if not value or value in (".", ".."):
        raise MetadataError("{} is empty or unsafe: {!r}".format(label, value))
    if "/" in value or "\\" in value or Path(value).name != value:
        raise MetadataError("{} contains a path separator: {!r}".format(label, value))


def safe_target(root: Path, tag: str, name: str) -> Path:
    """Return a target path while preventing release metadata path traversal."""

    _safe_component(tag, "release tag")
    _safe_component(name, "asset name")
    root = Path(root).resolve()
    target = (root / tag / name).resolve()
    try:
        target.relative_to(root)
    except ValueError as error:
        raise MetadataError("asset path escapes the output directory") from error
    return target


def verify_asset(path: Path, asset: Asset) -> bool:
    """Verify exact size and, when supplied by GitHub, SHA-256."""

    try:
        if not path.is_file() or path.stat().st_size != asset.size:
            return False
    except OSError:
        return False

    if not asset.digest:
        return True

    match = SHA256_RE.match(asset.digest)
    if not match:
        return False
    expected = match.group(1).lower()
    actual = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(CHUNK_SIZE)
                if not chunk:
                    break
                actual.update(chunk)
    except OSError:
        return False
    return actual.hexdigest() == expected


def _content_range_starts_at(value: Optional[str], offset: int) -> bool:
    if not value:
        return False
    match = re.match(r"^bytes\s+(\d+)-\d+/\d+$", value.strip(), re.IGNORECASE)
    return bool(match and int(match.group(1)) == offset)


def download_asset(
    asset: Asset,
    output_root: Path,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    opener: Callable = urlopen,
    sleeper: Callable[[float], None] = time.sleep,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    """Download one asset and return ``skipped``, ``downloaded`` or ``resumed``."""

    if retries < 1:
        raise ValueError("retries must be at least 1")

    target = safe_target(output_root, asset.tag, asset.name)
    part = target.with_name(target.name + ".part")
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        if verify_asset(target, asset):
            return "skipped"
        # A wrongly-sized or wrongly-hashed final file is not a trusted prefix.
        target.unlink()

    last_error = None
    for attempt in range(1, retries + 1):
        try:
            if part.exists():
                part_size = part.stat().st_size
                if part_size > asset.size:
                    part.unlink()
                elif part_size == asset.size:
                    if verify_asset(part, asset):
                        os.replace(str(part), str(target))
                        return "resumed"
                    part.unlink()

            offset = part.stat().st_size if part.exists() else 0
            request_headers = {
                "Accept": "application/octet-stream",
                "User-Agent": USER_AGENT,
            }
            if offset:
                request_headers["Range"] = "bytes={}-".format(offset)
                if progress:
                    progress("RESUME   {}/{} from {} bytes".format(asset.tag, asset.name, offset))
            elif progress:
                progress("DOWNLOAD {}/{}".format(asset.tag, asset.name))

            request = Request(asset.url, headers=request_headers)
            with opener(request, timeout=timeout) as response:
                status = getattr(response, "status", None) or response.getcode()
                resumed = False
                if offset and status == 206:
                    if not _content_range_starts_at(response.headers.get("Content-Range"), offset):
                        raise DownloadError("server returned an invalid Content-Range")
                    mode = "ab"
                    resumed = True
                elif status == 200:
                    # The server ignored Range; overwrite instead of appending duplicates.
                    mode = "wb"
                elif not offset and status == 206:
                    if not _content_range_starts_at(response.headers.get("Content-Range"), 0):
                        raise DownloadError("server returned an invalid Content-Range")
                    mode = "wb"
                else:
                    raise DownloadError("unexpected HTTP status {}".format(status))

                with part.open(mode) as handle:
                    while True:
                        chunk = response.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        handle.write(chunk)

            if not verify_asset(part, asset):
                actual_size = part.stat().st_size if part.exists() else 0
                if actual_size != asset.size:
                    reason = "size mismatch: expected {}, got {}".format(asset.size, actual_size)
                else:
                    reason = "SHA-256 mismatch"
                raise DownloadError(reason)

            os.replace(str(part), str(target))
            return "resumed" if resumed else "downloaded"

        except KeyboardInterrupt:
            raise
        except (HTTPError, URLError, OSError, DownloadError) as error:
            last_error = error
            if attempt < retries:
                sleeper(min(float(attempt), 3.0))

    raise DownloadError(
        "failed after {} attempt{}: {}".format(
            retries, "" if retries == 1 else "s", last_error
        )
    )


def run(
    output_root: Path,
    api_url: str = API_URL,
    token: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
) -> int:
    """Discover releases, process all assets, print a summary, and return an exit code."""

    try:
        release_count, assets = fetch_releases(api_url, token=token, timeout=timeout)
    except MetadataError as error:
        print("ERROR    {}".format(error))
        return 1

    skipped = 0
    downloaded = 0
    failed = 0

    for asset in assets:
        label = "{}/{}".format(asset.tag, asset.name)
        try:
            result = download_asset(
                asset,
                output_root,
                timeout=timeout,
                retries=retries,
                progress=print,
            )
            if result == "skipped":
                skipped += 1
                print("SKIP     {}".format(label))
            else:
                downloaded += 1
                print("OK       {}".format(label))
        except (MetadataError, DownloadError, OSError, ValueError) as error:
            failed += 1
            print("ERROR    {}: {}".format(label, error))

    print(
        "Releases: {}, assets: {}, skipped: {}, downloaded: {}, failed: {}".format(
            release_count, len(assets), skipped, downloaded, failed
        )
    )
    return 1 if failed else 0


def main() -> int:
    output_root = Path(__file__).resolve().parent
    token = os.environ.get("GITHUB_TOKEN") or None
    return run(output_root, token=token)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted; partial .part file kept for the next run.", file=sys.stderr)
        sys.exit(130)
