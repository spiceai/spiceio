#!/bin/bash
# Control-flow checks for download-release.sh. No network: gh and curl are fakes.
set -euo pipefail

root=$(cd "$(dirname "$0")" && pwd)
script="$root/download-release.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

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
cat > "$tmp/bin-no-gh/curl" <<'EOF'
#!/bin/bash
echo "curl-fail" >&2
exit 22
EOF
chmod +x "$tmp/bin-no-gh/curl"
set +e
out=$(PATH="$tmp/bin-no-gh:/usr/bin:/bin" \
  REPO=spiceai/spiceio VERSION=v0.11.0 INSTALL_DIR="$tmp/no-gh" \
  RUNNER_OS=macOS RUNNER_ARCH=ARM64 \
  env -u GH_TOKEN bash "$script" 2>&1)
rc=$?
set -e
[[ "$rc" -ne 0 ]] || fail "missing asset download succeeded"
[[ "$rc" -ne 127 ]] || fail "missing gh still exits 127"
printf '%s\n' "$out" | grep -q 'gh is not on PATH' || fail "error did not name gh: $out"

# No gh, curl writes the two assets, script exits 0.
mkdir -p "$tmp/bin-ok" "$tmp/ok"
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
PATH="$tmp/bin-ok:/usr/bin:/bin" \
  REPO=spiceai/spiceio VERSION=v0.11.0 INSTALL_DIR="$tmp/ok" \
  RUNNER_OS=macOS RUNNER_ARCH=ARM64 \
  bash "$script" >"$tmp/ok.out" 2>&1
[[ -s "$tmp/ok/spiceio-macOS-ARM64.tar.gz" ]] || fail "tarball was not written"
[[ -s "$tmp/ok/spiceio-macOS-ARM64.tar.gz.sha256" ]] || fail "checksum was not written"
grep -q 'gh is not on PATH' "$tmp/ok.out" || fail "fallback did not warn that gh is missing"

echo "ok"
