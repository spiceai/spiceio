#!/usr/bin/env bash
set -euo pipefail

# ── Configuration (override via environment) ────────────────────────────────

SMB_SERVER="${SPIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPIO_SMB_DOMAIN:-}"
REGION="${SPIO_REGION:-us-east-1}"
BUCKET="${SPIO_BUCKET:-sccache}"
BIND="${SPIO_BIND:-127.0.0.1:18333}"

: "${SPIO_SMB_USER:?SPIO_SMB_USER is required}"
: "${SPIO_SMB_PASS:?SPIO_SMB_PASS is required}"

SPIO_BIN="./target/debug/spio"
TEST_TARGET_DIR="./target/test-sccache"

# ── Cleanup on exit ─────────────────────────────────────────────────────────

SPIO_PID=""
cleanup() {
    echo "[test] cleaning up..."
    sccache --stop-server 2>/dev/null || true
    if [[ -n "$SPIO_PID" ]]; then
        kill "$SPIO_PID" 2>/dev/null || true
        wait "$SPIO_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ── Start spio ──────────────────────────────────────────────────────────────

echo "[test] starting spio -> smb://${SPIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"

SPIO_BIND="$BIND" \
SPIO_SMB_SERVER="$SMB_SERVER" \
SPIO_SMB_PORT="$SMB_PORT" \
SPIO_SMB_USER="$SPIO_SMB_USER" \
SPIO_SMB_PASS="$SPIO_SMB_PASS" \
SPIO_SMB_DOMAIN="$SMB_DOMAIN" \
SPIO_SMB_SHARE="$SMB_SHARE" \
SPIO_BUCKET="$BUCKET" \
SPIO_REGION="$REGION" \
"$SPIO_BIN" &
SPIO_PID=$!

# Wait for spio to accept connections
echo "[test] waiting for spio on ${BIND}..."
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "http://${BIND}/" 2>/dev/null; then
        echo "[test] spio ready"
        break
    fi
    if ! kill -0 "$SPIO_PID" 2>/dev/null; then
        echo "[test] spio exited unexpectedly"
        exit 1
    fi
    sleep 0.5
done

# ── Configure sccache ──────────────────────────────────────────────────────

echo "[test] configuring sccache -> http://${BIND}/${BUCKET}"
sccache --stop-server 2>/dev/null || true

export SCCACHE_BUCKET="$BUCKET"
export SCCACHE_ENDPOINT="http://${BIND}"
export SCCACHE_REGION="$REGION"
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX="spio/${REGION}/${BUCKET}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache

sccache --start-server
sccache --zero-stats 2>/dev/null || true

# ── Cold build ──────────────────────────────────────────────────────────────

echo ""
echo "[test] === cold build (populating cache) ==="
rm -rf "$TEST_TARGET_DIR"
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1

# ── Warm build ──────────────────────────────────────────────────────────────

echo ""
echo "[test] === warm build (should hit cache) ==="
rm -rf "$TEST_TARGET_DIR"
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1

# ── Stats ───────────────────────────────────────────────────────────────────

echo ""
echo "======================================="
echo "[test] sccache stats:"
echo "======================================="
sccache --show-stats
echo "======================================="
