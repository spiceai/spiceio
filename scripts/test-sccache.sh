#!/usr/bin/env bash
set -euo pipefail

# ── Configuration (override via environment) ────────────────────────────────

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-sccache}"
BIND="${SPICEIO_BIND:-127.0.0.1:18333}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/debug/spiceio"
TEST_TARGET_DIR="./target/test-sccache"
ENDPOINT="http://${BIND}"
AWS="aws --endpoint-url $ENDPOINT --no-sign-request"
TEST_PREFIX="spiceio-test-$$"
PASS=0
FAIL=0

# ── Cleanup on exit ─────────────────────────────────────────────────────────

SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[test] cleaning up..."
    sccache --stop-server 2>/dev/null || true
    # Remove test objects
    $AWS s3 rm "s3://${BUCKET}/${TEST_PREFIX}/" --recursive 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf /tmp/spiceio-test-*
}
trap cleanup EXIT

# ── Test helpers ────────────────────────────────────────────────────────────

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

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected to contain '$needle')"
        FAIL=$((FAIL + 1))
    fi
}

assert_ok() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (exit code $?)"
        FAIL=$((FAIL + 1))
    fi
}

assert_fail() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  FAIL: $label (expected failure but succeeded)"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    fi
}

# ── Start spiceio ───────────────────────────────────────────────────────────

echo "[test] starting spiceio -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"

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

# ════════════════════════════════════════════════════════════════════════════
# AWS CLI S3 API tests
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] AWS CLI S3 API tests"
echo "======================================="

# ── ListBuckets ─────────────────────────────────────────────────────────────

echo ""
echo "[s3] ListBuckets"
BUCKETS=$($AWS s3 ls 2>&1)
assert_contains "ListBuckets contains bucket" "$BUCKET" "$BUCKETS"

# ── HeadBucket ──────────────────────────────────────────────────────────────

echo ""
echo "[s3] HeadBucket"
assert_ok "HeadBucket on existing bucket" $AWS s3api head-bucket --bucket "$BUCKET"

# ── PutObject + GetObject (small) ───────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (small)"
echo "hello spiceio" > /tmp/spiceio-test-small.txt
$AWS s3 cp /tmp/spiceio-test-small.txt "s3://${BUCKET}/${TEST_PREFIX}/small.txt" --quiet 2>/dev/null
GOT=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" - 2>/dev/null)
assert_eq "small file round-trip" "hello spiceio" "$GOT"

# ── PutObject + GetObject (64KB) ────────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (64KB)"
dd if=/dev/urandom of=/tmp/spiceio-test-64k.bin bs=1024 count=64 2>/dev/null
$AWS s3 cp /tmp/spiceio-test-64k.bin "s3://${BUCKET}/${TEST_PREFIX}/64k.bin" --quiet 2>/dev/null
$AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/64k.bin" /tmp/spiceio-test-64k-dl.bin --quiet 2>/dev/null
ORIG_MD5=$(md5 -q /tmp/spiceio-test-64k.bin)
DL_MD5=$(md5 -q /tmp/spiceio-test-64k-dl.bin)
assert_eq "64KB file integrity" "$ORIG_MD5" "$DL_MD5"

# ── PutObject + GetObject (1MB) ─────────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (1MB)"
dd if=/dev/urandom of=/tmp/spiceio-test-1m.bin bs=1024 count=1024 2>/dev/null
$AWS s3 cp /tmp/spiceio-test-1m.bin "s3://${BUCKET}/${TEST_PREFIX}/1m.bin" --quiet 2>/dev/null
$AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/1m.bin" /tmp/spiceio-test-1m-dl.bin --quiet 2>/dev/null
ORIG_MD5=$(md5 -q /tmp/spiceio-test-1m.bin)
DL_MD5=$(md5 -q /tmp/spiceio-test-1m-dl.bin)
assert_eq "1MB file integrity" "$ORIG_MD5" "$DL_MD5"

# ── HeadObject ──────────────────────────────────────────────────────────────

echo ""
echo "[s3] HeadObject"
HEAD=$($AWS s3api head-object --bucket "$BUCKET" --key "${TEST_PREFIX}/small.txt" 2>/dev/null)
assert_contains "HeadObject has ContentLength" "ContentLength" "$HEAD"

# ── ListObjectsV2 ──────────────────────────────────────────────────────────

echo ""
echo "[s3] ListObjectsV2"
LIST=$($AWS s3 ls "s3://${BUCKET}/${TEST_PREFIX}/" 2>&1 || true)
assert_contains "list contains small.txt" "small.txt" "$LIST"
assert_contains "list contains 64k.bin" "64k.bin" "$LIST"
assert_contains "list contains 1m.bin" "1m.bin" "$LIST"

# ── CopyObject ──────────────────────────────────────────────────────────────

echo ""
echo "[s3] CopyObject"
$AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" "s3://${BUCKET}/${TEST_PREFIX}/copy.txt" --quiet 2>/dev/null
COPY=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/copy.txt" - 2>/dev/null)
assert_eq "copy content matches" "hello spiceio" "$COPY"

# ── DeleteObject ────────────────────────────────────────────────────────────

echo ""
echo "[s3] DeleteObject"
assert_ok "delete copy.txt" $AWS s3 rm "s3://${BUCKET}/${TEST_PREFIX}/copy.txt"
assert_fail "head deleted object fails" $AWS s3api head-object --bucket "$BUCKET" --key "${TEST_PREFIX}/copy.txt"

# ── Nested paths ────────────────────────────────────────────────────────────

echo ""
echo "[s3] Nested paths"
echo "deep content" | $AWS s3 cp - "s3://${BUCKET}/${TEST_PREFIX}/a/b/c/deep.txt" --quiet 2>/dev/null
DEEP=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/a/b/c/deep.txt" - 2>/dev/null)
assert_eq "nested path round-trip" "deep content" "$DEEP"

# ── Overwrite ───────────────────────────────────────────────────────────────

echo ""
echo "[s3] Overwrite"
echo "version2" | $AWS s3 cp - "s3://${BUCKET}/${TEST_PREFIX}/small.txt" --quiet 2>/dev/null
GOT=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" - 2>/dev/null)
assert_eq "overwrite content" "version2" "$GOT"

# ── AWS CLI summary ─────────────────────────────────────────────────────────

echo ""
echo "======================================="
echo "[test] AWS CLI: $PASS passed, $FAIL failed"
echo "======================================="

if [[ "$FAIL" -gt 0 ]]; then
    echo "[test] ABORTING — S3 API tests failed"
    exit 1
fi

# ════════════════════════════════════════════════════════════════════════════
# sccache integration test
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] sccache integration test"
echo "======================================="

sccache --stop-server 2>/dev/null || true

export SCCACHE_BUCKET="$BUCKET"
export SCCACHE_ENDPOINT="$ENDPOINT"
export SCCACHE_REGION="$REGION"
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX="spiceio/${REGION}/${BUCKET}"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache

sccache --start-server
sccache --zero-stats 2>/dev/null || true

echo ""
echo "[test] === cold build (populating cache) ==="
rm -rf "$TEST_TARGET_DIR"
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1

echo ""
echo "[test] === warm build (should hit cache) ==="
rm -rf "$TEST_TARGET_DIR"
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1

echo ""
echo "======================================="
echo "[test] sccache stats:"
echo "======================================="
sccache --show-stats
echo "======================================="

# ── Verify cache hits ───────────────────────────────────────────────────────

STATS=$(sccache --show-stats 2>&1)
CACHE_HITS=$(echo "$STATS" | grep -m1 "^Cache hits" | awk '{print $NF}')
WRITE_ERRORS=$(echo "$STATS" | grep -m1 "Cache write errors" | awk '{print $NF}')

echo ""
if [[ "${CACHE_HITS:-0}" -gt 0 && "${WRITE_ERRORS:-0}" -eq 0 ]]; then
    echo "[test] PASS: warm build got $CACHE_HITS cache hits, 0 write errors"
else
    echo "[test] FAIL: expected cache hits > 0 (got ${CACHE_HITS:-0}) and write errors == 0 (got ${WRITE_ERRORS:-0})"
    exit 1
fi
