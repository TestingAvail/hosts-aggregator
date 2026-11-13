#!/usr/bin/env python3
"""Keep only the newest N GitHub releases and remove their tags."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def api_request(url: str, token: str, method: str = "GET"):
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "hosts-aggregator-release-maintenance",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        if method == "DELETE" and error.code == 404:
            return None
        raise


def list_all_releases(api: str, token: str) -> list[dict]:
    """Fetch every release page; pruning must not stop at GitHub's 100-item cap."""
    releases: list[dict] = []
    page = 1
    while True:
        batch = api_request(f"{api}/releases?per_page=100&page={page}", token) or []
        if not batch:
            break
        releases.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return releases


def select_stale_releases(releases: list[dict], keep: int) -> list[dict]:
    """Return only old releases owned by this project, never unrelated tags."""
    owned = [item for item in releases if str(item.get("tag_name", "")).startswith("hosts-")]
    owned.sort(
        key=lambda item: item.get("published_at") or item.get("created_at") or "",
        reverse=True,
    )
    return owned[keep:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep", type=int, default=30)
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not token or not repo:
        print("GITHUB_TOKEN and GITHUB_REPOSITORY are required", file=sys.stderr)
        return 2
    if args.keep < 1:
        parser.error("--keep must be >= 1")

    api = f"https://api.github.com/repos/{repo}"
    releases = list_all_releases(api, token)
    # Never touch manually created releases or releases owned by another tool.
    owned_count = sum(1 for item in releases if str(item.get("tag_name", "")).startswith("hosts-"))
    stale = select_stale_releases(releases, args.keep)
    for release in stale:
        release_id = release["id"]
        tag = release.get("tag_name", "")
        api_request(f"{api}/releases/{release_id}", token, "DELETE")
        if tag:
            encoded = urllib.parse.quote(tag, safe="")
            api_request(f"{api}/git/refs/tags/{encoded}", token, "DELETE")
        print(f"Deleted old release: {tag}")
    print(f"Kept {min(owned_count, args.keep)} newest project release(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
