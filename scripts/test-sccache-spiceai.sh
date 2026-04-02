#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Extended sccache integration test — builds the spiceai repository through
# spiceio's S3-to-SMB proxy. Skipped when ~/dev/spiceai is not present.
# ═══════════════════════════════════════════════════════════════════════════

SPICEAI_DIR="${HOME}/dev/spiceai"

if [[ ! -d "$SPICEAI_DIR" || ! -f "$SPICEAI_DIR/Cargo.toml" ]]; then
    echo "[test] SKIP: ${SPICEAI_DIR} not found — skipping spiceai extended test"
    exit 0
fi

# ── Configuration (override via environment) ──────────────────────────────

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-sccache}"
BIND="${SPICEIO_BIND_EXT:-127.0.0.1:18334}"  # separate port from base test

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/debug/spiceio"
ENDPOINT="http://${BIND}"
TEST_TARGET_DIR="${SPICEAI_DIR}/target/test-sccache-spiceio"
PASS=0
FAIL=0

# ── Cleanup on exit ──────────────────────────────────────────────────────

SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[test] cleaning up..."
    sccache --stop-server 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_TARGET_DIR"
}
trap cleanup EXIT

# ── Test helpers ─────────────────────────────────────────────────────────

assert_gt() {
    local label="$1" threshold="$2" actual="$3"
    if [[ "$actual" -gt "$threshold" ]]; then
        echo "  PASS: $label ($actual > $threshold)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected > $threshold, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected='$expected', got='$actual')"
        FAIL=$((FAIL + 1))
    fi
}

# ── Start spiceio ────────────────────────────────────────────────────────

echo "======================================="
echo "[test] spiceai sccache extended test"
echo "======================================="
echo ""
echo "[test] spiceai repo: ${SPICEAI_DIR}"
echo "[test] starting spiceio -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"

# ── Kill stale listener on our port ───────────────────────────────────────
BIND_PORT="${BIND##*:}"
STALE_PID=$(lsof -i ":${BIND_PORT}" -sTCP:LISTEN -t 2>/dev/null || true)
if [[ -n "$STALE_PID" ]]; then
    echo "[test] port ${BIND_PORT} already in use (pid ${STALE_PID}), killing..."
    kill "$STALE_PID" 2>/dev/null || true
    sleep 1
fi

SPICEIO_BIND="$BIND" \
SPICEIO_SMB_SERVER="$SMB_SERVER" \
SPICEIO_SMB_PORT="$SMB_PORT" \
SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
SPICEIO_SMB_SHARE="$SMB_SHARE" \
SPICEIO_BUCKET="$BUCKET" \
SPICEIO_REGION="$REGION" \
"$SPICEIO_BIN" &
SPICEIO_PID=$!

echo "[test] waiting for spiceio on ${BIND}..."
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "${ENDPOINT}/" 2>/dev/null; then
        echo "[test] spiceio ready"
        break
    fi
    if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
        echo "[test] spiceio exited unexpectedly"
        exit 1
    fi
    sleep 0.5
done

# ── Configure sccache ───────────────────────────────────────────────────

sccache --stop-server 2>/dev/null || true

export SCCACHE_BUCKET="$BUCKET"
export SCCACHE_ENDPOINT="$ENDPOINT"
export SCCACHE_REGION="$REGION"
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX="sccache"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0  # sccache cannot cache incremental builds

sccache --start-server
sccache --zero-stats 2>/dev/null || true

# ════════════════════════════════════════════════════════════════════════
# Cold build — populate cache
# ════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] cold build — spiceai CLI (populating cache)"
echo "======================================="

rm -rf "$TEST_TARGET_DIR"
COLD_START=$(date +%s)
CARGO_TARGET_DIR="$TEST_TARGET_DIR" \
    cargo build -p spice --manifest-path "$SPICEAI_DIR/Cargo.toml" 2>&1
COLD_END=$(date +%s)
COLD_SECS=$((COLD_END - COLD_START))

echo ""
echo "[test] cold build completed in ${COLD_SECS}s"

COLD_STATS=$(sccache --show-stats 2>&1)
COLD_MISSES=$(echo "$COLD_STATS" | grep -m1 "^Cache misses" | awk '{print $NF}' || echo "0")
COLD_ERRORS=$(echo "$COLD_STATS" | grep -m1 "Cache write errors" | awk '{print $NF}' || echo "0")
echo "[test] cold build stats: ${COLD_MISSES} misses, ${COLD_ERRORS} write errors"

# ════════════════════════════════════════════════════════════════════════
# Warm build — verify cache hits
# ════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] warm build — spiceai CLI (should hit cache)"
echo "======================================="

rm -rf "$TEST_TARGET_DIR"
sccache --zero-stats 2>/dev/null || true

WARM_START=$(date +%s)
CARGO_TARGET_DIR="$TEST_TARGET_DIR" \
    cargo build -p spice --manifest-path "$SPICEAI_DIR/Cargo.toml" 2>&1
WARM_END=$(date +%s)
WARM_SECS=$((WARM_END - WARM_START))

echo ""
echo "[test] warm build completed in ${WARM_SECS}s"

# ════════════════════════════════════════════════════════════════════════
# Verify cache stats & performance
# ════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] sccache stats (warm build):"
echo "======================================="
sccache --show-stats
echo "======================================="

STATS=$(sccache --show-stats 2>&1)
CACHE_HITS=$(echo "$STATS" | grep -m1 "^Cache hits" | awk '{print $NF}' || echo "0")
CACHE_MISSES=$(echo "$STATS" | grep -m1 "^Cache misses" | awk '{print $NF}' || echo "0")
WRITE_ERRORS=$(echo "$STATS" | grep -m1 "Cache write errors" | awk '{print $NF}' || echo "0")

echo ""
echo "[test] Performance:"
echo "  Cold build: ${COLD_SECS}s"
echo "  Warm build: ${WARM_SECS}s"
if [[ "$COLD_SECS" -gt 0 ]]; then
    SPEEDUP=$(( (COLD_SECS - WARM_SECS) * 100 / COLD_SECS ))
    echo "  Speedup:    ${SPEEDUP}%"
fi

echo ""
echo "[test] Cache (warm build):"
echo "  Hits:         ${CACHE_HITS}"
echo "  Misses:       ${CACHE_MISSES}"
echo "  Write errors: ${WRITE_ERRORS}"

# ── Assertions ───────────────────────────────────────────────────────────

echo ""
echo "======================================="
echo "[test] Assertions"
echo "======================================="

assert_gt  "warm build cache hits > 0"   0   "${CACHE_HITS:-0}"
assert_eq  "warm build write errors == 0" "0" "${WRITE_ERRORS:-0}"

# Cold build tolerates a small number of transient write errors (SMB over network)
if [[ "${COLD_ERRORS:-0}" -le 5 ]]; then
    echo "  PASS: cold build write errors <= 5 (got ${COLD_ERRORS:-0})"
    PASS=$((PASS + 1))
else
    echo "  FAIL: cold build write errors > 5 (got ${COLD_ERRORS:-0})"
    FAIL=$((FAIL + 1))
fi

# Cache hit rate must be >90% (misses are proc-macros and build scripts)
TOTAL_EXECUTED=$((CACHE_HITS + CACHE_MISSES))
if [[ "$TOTAL_EXECUTED" -gt 0 ]]; then
    HIT_RATE=$(( CACHE_HITS * 100 / TOTAL_EXECUTED ))
    if [[ "$HIT_RATE" -ge 90 ]]; then
        echo "  PASS: cache hit rate ${HIT_RATE}% >= 90%"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: cache hit rate ${HIT_RATE}% < 90%"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  FAIL: no cache-eligible compilations executed"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "======================================="
echo "[test] spiceai extended: $PASS passed, $FAIL failed"
echo "======================================="

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
