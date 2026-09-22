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

# Private repos 404 the public URL. The asset API 302s to a signed URL on
# another host. github_fetch.py sends GH_TOKEN only while the origin is
# api.github.com and strips Authorization on that hop (stock urllib keeps it).
download_private() {
  local name="$1"
  local here
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  python3 "$here/github_fetch.py" "$REPO" "$VERSION" "$INSTALL_DIR" "$name"
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
