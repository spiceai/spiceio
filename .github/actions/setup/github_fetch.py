#!/usr/bin/env python3
"""Download a GitHub release asset through the releases API.

The asset endpoint 302s to a signed URL on another host. CPython's
``urllib.request`` copies ``Authorization`` onto that hop, so a workflow
token would be sent to ``release-assets.githubusercontent.com``. This
opener drops the header whenever the origin (scheme + host + port) changes.
Same-origin redirects still carry the token.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_API_BASE = "https://api.github.com"
USER_AGENT = "spiceio-setup"


class StripAuthOnHostChange(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never take Authorization to a new origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        if _origin(req.full_url) != _origin(new.full_url):
            _drop_authorization(new)
        return new


def _origin(url: str) -> tuple[str, str]:
    parts = urllib.parse.urlsplit(url)
    return (parts.scheme.lower(), parts.netloc.lower())


def _drop_authorization(req: urllib.request.Request) -> None:
    for store in (req.headers, req.unredirected_hdrs):
        for key in [k for k in store if k.lower() == "authorization"]:
            store.pop(key, None)


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(StripAuthOnHostChange)


def fetch(url: str, accept: str, token: str = "") -> bytes:
    req = urllib.request.Request(url)
    req.add_header("Accept", accept)
    req.add_header("User-Agent", USER_AGENT)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with opener().open(req) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"GitHub API HTTP {err.code} fetching {url}: {body}") from err


def download_asset(
    repo: str,
    version: str,
    dest: str,
    name: str,
    token: str,
    api_base: str = DEFAULT_API_BASE,
) -> None:
    api_base = api_base.rstrip("/")
    if version == "latest":
        release_url = f"{api_base}/repos/{repo}/releases/latest"
    else:
        release_url = f"{api_base}/repos/{repo}/releases/tags/{version}"

    try:
        release = json.loads(fetch(release_url, "application/vnd.github+json", token))
    except RuntimeError as err:
        sys.stderr.write(f"::error::{err}\n")
        sys.exit(1)

    match = next((a for a in release.get("assets", []) if a.get("name") == name), None)
    if match is None:
        have = ", ".join(sorted(a.get("name", "") for a in release.get("assets", []))) or "none"
        sys.stderr.write(
            f"::error::release {version} of {repo} has no asset {name} (have: {have})\n"
        )
        sys.exit(1)

    try:
        data = fetch(match["url"], "application/octet-stream", token)
    except RuntimeError as err:
        sys.stderr.write(f"::error::{err}\n")
        sys.exit(1)

    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, name), "wb") as fh:
        fh.write(data)


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 4:
        sys.stderr.write("usage: github_fetch.py REPO VERSION DEST NAME\n")
        sys.exit(2)
    repo, version, dest, name = args
    token = os.environ.get("GH_TOKEN", "")
    api_base = os.environ.get("GITHUB_API_BASE", DEFAULT_API_BASE)
    download_asset(repo, version, dest, name, token, api_base=api_base)


if __name__ == "__main__":
    main()
