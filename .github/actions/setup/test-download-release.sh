#!/bin/bash
# Control-flow checks for download-release.sh, plus the urllib redirect gate.
# No GitHub network: gh and curl are fakes; the private-API hop is loopback.
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
script="$root/download-release.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# This image has /usr/bin/gh. The no-gh cases must not see it, but they
# still need python3 (releases-API fallback) and mkdir/dirname.
path_without_gh() {
  local extra="$1"
  mkdir -p "$extra"
  local tool
  for tool in python3 python3.12 mkdir dirname; do
    if command -v "$tool" >/dev/null 2>&1; then
      ln -sfn "$(command -v "$tool")" "$extra/$tool"
    fi
  done
  printf '%s' "$extra"
}

# gh on PATH is used and curl is not.
mkdir -p "$tmp/bin" "$tmp/with-gh"
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" > "$INSTALL_DIR/gh-args"
EOF
cat > "$tmp/bin/curl" <<'EOF'
#!/bin/bash
echo "curl should not run" > "$INSTALL_DIR/curl-ran"
exit 1
EOF
chmod +x "$tmp/bin/gh" "$tmp/bin/curl"
PATH="$tmp/bin:/usr/bin:/bin" \
  REPO=spiceai/spiceio VERSION=v0.11.0 INSTALL_DIR="$tmp/with-gh" \
  RUNNER_OS=macOS RUNNER_ARCH=ARM64 \
  bash "$script"
grep -q 'release download' "$tmp/with-gh/gh-args" || fail "gh was not invoked"
[[ ! -e "$tmp/with-gh/curl-ran" ]] || fail "curl ran even though gh was on PATH"

# No gh: curl downloads each asset. A failing public URL with no token is an error
# that names gh, not a bare exit 127.
mkdir -p "$tmp/bin-no-gh" "$tmp/no-gh"
path_without_gh "$tmp/bin-no-gh" >/dev/null
cat > "$tmp/bin-no-gh/curl" <<'EOF'
#!/bin/bash
echo "curl-fail" >&2
exit 22
EOF
chmod +x "$tmp/bin-no-gh/curl"
set +e
out=$(PATH="$(path_without_gh "$tmp/bin-no-gh")" \
  REPO=spiceai/spiceio VERSION=v0.11.0 INSTALL_DIR="$tmp/no-gh" \
  RUNNER_OS=macOS RUNNER_ARCH=ARM64 \
  /usr/bin/env -u GH_TOKEN /bin/bash "$script" 2>&1)
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "missing asset download succeeded"
[[ "$rc" -ne 127 ]] || fail "missing gh still exits 127"
printf '%s\n' "$out" | grep -q 'gh is not on PATH' || fail "error did not name gh: $out"

# No gh, curl writes the two assets, script exits 0.
mkdir -p "$tmp/bin-ok" "$tmp/ok"
path_without_gh "$tmp/bin-ok" >/dev/null
cat > "$tmp/bin-ok/curl" <<'EOF'
#!/bin/bash
out=""
prev=""
for arg in "$@"; do
  if [[ "$prev" == "-o" ]]; then
    out="$arg"
  fi
  prev="$arg"
done
printf 'ok\n' > "$out"
EOF
chmod +x "$tmp/bin-ok/curl"
PATH="$(path_without_gh "$tmp/bin-ok")" \
  REPO=spiceai/spiceio VERSION=v0.11.0 INSTALL_DIR="$tmp/ok" \
  RUNNER_OS=macOS RUNNER_ARCH=ARM64 \
  /bin/bash "$script" >"$tmp/ok.out" 2>&1
[[ -s "$tmp/ok/spiceio-macOS-ARM64.tar.gz" ]] || fail "tarball was not written"
[[ -s "$tmp/ok/spiceio-macOS-ARM64.tar.gz.sha256" ]] || fail "checksum was not written"
grep -q 'gh is not on PATH' "$tmp/ok.out" || fail "fallback did not warn that gh is missing"

# Two-server Authorization leak: stock urllib forwards the token; github_fetch
# must not. Also exercises download_asset against a loopback GitHub API.
python3 "$root/test-github-fetch.py" || fail "github_fetch redirect tests failed"

echo "ok"
