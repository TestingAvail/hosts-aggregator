#!/usr/bin/env python3
"""Keep the newest N GitHub Releases and remove their old release tags."""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

OWNED_RELEASE_TAG_PREFIX = "hosts-aggregator-"
LEGACY_RELEASE_TAG = re.compile(r"^hosts-\d+-\d+$")


def is_owned_release(release: dict) -> bool:
    """Recognize current tags and the previous numeric build-tag format."""
    tag = str(release.get("tag_name", ""))
    return tag.startswith(OWNED_RELEASE_TAG_PREFIX) or bool(LEGACY_RELEASE_TAG.fullmatch(tag))


def parse_date(release: dict) -> str:
    return release.get("published_at") or release.get("created_at") or ""


def select_releases_to_delete(releases: list[dict], keep: int = 30) -> list[dict]:
    """Select stale releases created by this builder only."""
    owned = [release for release in releases if is_owned_release(release)]
    ordered = sorted(owned, key=parse_date, reverse=True)
    return ordered[max(0, keep):]


def api_request(url: str, token: str, method: str = "GET"):
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hosts-aggregator-release-pruner",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read()
            return json.loads(payload) if payload else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"GitHub API {method} {url}: HTTP {exc.code}: {body[:500]}") from exc


def fetch_releases(repository: str, token: str) -> list[dict]:
    releases: list[dict] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/releases?per_page=100&page={page}"
        batch = api_request(url, token)
        if not isinstance(batch, list):
            raise RuntimeError("Unexpected GitHub Releases API response")
        releases.extend(batch)
        if len(batch) < 100:
            return releases
        page += 1


def delete_release(repository: str, token: str, release: dict) -> None:
    release_id = release["id"]
    tag = release.get("tag_name", "")
    api_request(f"https://api.github.com/repos/{repository}/releases/{release_id}", token, "DELETE")
    if tag:
        quoted = urllib.parse.quote(tag, safe="")
        ref_url = f"https://api.github.com/repos/{repository}/git/refs/tags/{quoted}"
        try:
            api_request(ref_url, token, "DELETE")
        except RuntimeError as exc:
            # Release deletion succeeded; missing or protected tag should not
            # turn the entire cleanup into a false failure.
            print(f"WARNING: release removed but tag {tag!r} was not: {exc}", file=sys.stderr)
    print(f"Deleted release: {tag or release_id}")


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    keep = int(os.environ.get("KEEP_RELEASES", "30"))
    if not repository or "/" not in repository:
        raise SystemExit("GITHUB_REPOSITORY is missing or invalid")
    if not token:
        raise SystemExit("GITHUB_TOKEN is missing")
    if keep < 1:
        raise SystemExit("KEEP_RELEASES must be >= 1")
    releases = fetch_releases(repository, token)
    old = select_releases_to_delete(releases, keep)
    print(f"Repository: {repository}; releases: {len(releases)}; keeping: {keep}; deleting: {len(old)}")
    for release in old:
        delete_release(repository, token, release)
    print("Release cleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
