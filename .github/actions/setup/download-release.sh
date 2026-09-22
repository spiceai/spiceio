#!/bin/bash
# Download a spiceio release asset and its .sha256 into INSTALL_DIR.
#
# Prefer `gh release download` when the CLI is on PATH. A macOS Actions runner
# whose .path file was snapshotted without Homebrew does not have `gh`, and
# `set -e` then exits 127 inside "Set up spiceio" (spiceai/spiceai#14233,
# spiceai/spiceai#14234). Fall back to the public release URL, then the
# releases API, so a missing CLI is a warning rather than a dead job.
set -euo pipefail

: "${REPO:?REPO is required}"
: "${VERSION:?VERSION is required}"
: "${INSTALL_DIR:?INSTALL_DIR is required}"
: "${RUNNER_OS:?RUNNER_OS is required}"
: "${RUNNER_ARCH:?RUNNER_ARCH is required}"

ASSET="spiceio-${RUNNER_OS}-${RUNNER_ARCH}.tar.gz"
mkdir -p "$INSTALL_DIR"

download_with_gh() {
  if [[ "$VERSION" == "latest" ]]; then
    gh release download --repo "$REPO" --pattern "$ASSET" --pattern "${ASSET}.sha256" --dir "$INSTALL_DIR"
  else
    gh release download "$VERSION" --repo "$REPO" --pattern "$ASSET" --pattern "${ASSET}.sha256" --dir "$INSTALL_DIR"
  fi
}

# Public releases are served from this URL with no token. `latest` is the
# GitHub alias, not a tag we invent.
public_url() {
  local name="$1"
  if [[ "$VERSION" == "latest" ]]; then
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$name"
  else
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$name"
  fi
}

download_public() {
  local name="$1"
  curl -fsSL --retry 3 --retry-delay 2 -o "${INSTALL_DIR}/${name}" "$(public_url "$name")"
}

# Private repos 404 the public URL. The asset API redirects to a signed URL;
# curl must send the token only on the first hop (it strips Authorization on
# cross-host redirects by default).
download_private() {
  local name="$1"
  python3 - "$REPO" "$VERSION" "$INSTALL_DIR" "$name" <<'PY'
import json, os, sys, urllib.error, urllib.request

repo, version, dest, name = sys.argv[1:]
token = os.environ.get("GH_TOKEN", "")
if version == "latest":
    release_url = f"https://api.github.com/repos/{repo}/releases/latest"
else:
    release_url = f"https://api.github.com/repos/{repo}/releases/tags/{version}"

def fetch(url, accept):
    req = urllib.request.Request(url)
    req.add_header("Accept", accept)
    req.add_header("User-Agent", "spiceio-setup")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        body = err.read().decode("utf-8", "replace")[:300]
        sys.stderr.write(f"::error::GitHub API HTTP {err.code} fetching release asset {name}: {body}\n")
        sys.exit(1)

release = json.loads(fetch(release_url, "application/vnd.github+json"))
match = next((a for a in release.get("assets", []) if a.get("name") == name), None)
if match is None:
    have = ", ".join(sorted(a.get("name", "") for a in release.get("assets", []))) or "none"
    sys.stderr.write(f"::error::release {version} of {repo} has no asset {name} (have: {have})\n")
    sys.exit(1)
data = fetch(match["url"], "application/octet-stream")
with open(os.path.join(dest, name), "wb") as fh:
    fh.write(data)
PY
}

download_without_gh() {
  echo "::warning title=gh is not on PATH::Set up spiceio runs 'gh release download' and gh is not on PATH. Downloading ${ASSET} with curl. Install the GitHub CLI on this runner and include /opt/homebrew/bin in the runner .path file."
  local name
  for name in "$ASSET" "${ASSET}.sha256"; do
    if ! download_public "$name"; then
      if [[ -z "${GH_TOKEN:-}" ]]; then
        echo "::error title=gh is not on PATH::Could not download ${name} from $(public_url "$name") and GH_TOKEN is empty, so the releases API cannot be used. Install gh or provide the token input."
        exit 1
      fi
      if ! command -v python3 >/dev/null 2>&1; then
        echo "::error title=gh is not on PATH::Could not download ${name} from the public release URL, and python3 is not available for the releases API fallback. Install gh on this runner."
        exit 1
      fi
      download_private "$name"
    fi
  done
}

if command -v gh >/dev/null 2>&1; then
  download_with_gh
else
  download_without_gh
fi
