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
NAS_BIN="./target/debug/spiceio-sccache-nas"
TEST_TARGET_DIR="./target/test-sccache"
ENDPOINT="http://${BIND}"
# Pass --region explicitly: AWS CLI errors out without one on some runners
# (no AWS_DEFAULT_REGION in env, no ~/.aws/config).
AWS="aws --endpoint-url $ENDPOINT --no-sign-request --region $REGION"
# $$ is reused after wraparound; a random token keeps an interrupted run's
# leftover objects from satisfying a later run's cache-hit / durability checks.
TEST_TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
TEST_PREFIX="spiceio-test-$$-${TEST_TOKEN}"
# Isolate this run's compiler cache. A shared prefix would let the
# post-shutdown NAS check pass on leftover objects from a previous run.
SCCACHE_PREFIX="${TEST_PREFIX}/sccache"
TEST_WORK=$(mktemp -d /tmp/spiceio-sccache-work.XXXXXX)
NAS_MANIFEST="${TEST_WORK}/sccache-nas-manifest.json"
# Local smbfs mount of the same share. Off by default: CI runners do not
# have one, so the NAS check reads back through a cache-less spiceio.
# Opt in locally with SPICEIO_SMB_MOUNT=/Volumes/ai_platform_dev.
SMB_MOUNT="${SPICEIO_SMB_MOUNT:-off}"
# Never stop or reconfigure a developer's default sccache daemon.
if [[ -z "${SCCACHE_SERVER_PORT:-}" ]]; then
    SCCACHE_SERVER_PORT=$(python3 - <<'PORT'
import socket
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PORT
)
fi
export SCCACHE_SERVER_PORT
PASS=0
FAIL=0

# Capture spiceio stderr so the post-run guard can flag unexpected
# `[spiceio] error:` lines. We tee back to stderr so CI still streams live.
SPICEIO_STDERR=$(mktemp /tmp/spiceio-sccache-stderr.XXXXXX)

nas_mount_requested() {
    [[ -n "$SMB_MOUNT" && "$SMB_MOUNT" != "off" && "$SMB_MOUNT" != "0" && "$SMB_MOUNT" != "false" ]]
}

nas_mount_ready() {
    nas_mount_requested || return 1
    [[ -d "$SMB_MOUNT" ]] || return 1
    # Require smbfs, not merely "something is mounted here" (APFS/local would
    # let the durability check hash a local directory and then rm -rf it).
    mount | grep -F " on ${SMB_MOUNT} (smbfs" >/dev/null
}

# ── Cleanup on exit ─────────────────────────────────────────────────────────

SPICEIO_PID=""
SPICEIO_PID2=""
cleanup() {
    echo ""
    echo "[test] cleaning up..."
    sccache --stop-server 2>/dev/null || true
    # Remove test objects. Prefer the local mount when spiceio is already
    # down; AWS CLI against a dead proxy is a no-op.
    $AWS s3 rm "s3://${BUCKET}/${TEST_PREFIX}/" --recursive 2>/dev/null || true
    if nas_mount_ready && [[ -d "${SMB_MOUNT}/${TEST_PREFIX}" ]]; then
        rm -rf "${SMB_MOUNT}/${TEST_PREFIX}" 2>/dev/null || true
    fi
    if [[ -n "$SPICEIO_PID2" ]]; then
        kill "$SPICEIO_PID2" 2>/dev/null || true
        wait "$SPICEIO_PID2" 2>/dev/null || true
    fi
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$TEST_WORK"
    rm -f "$SPICEIO_STDERR"
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

# SIGTERM, wait for the process, then for this process's own shutdown lines
# to land in the log. The capture file is shared, so we only inspect bytes
# written after the kill — a peer's earlier "shutting down" must not count.
# Sets STOP_LOG / STOP_LOG_OFFSET for callers that grep the suffix.
stop_spiceio() {
    local __pidvar="$1" pid="${!1}"
    local log="${2:-$SPICEIO_STDERR}"
    [[ -z "$pid" ]] && return 0
    local offset=0
    if [[ -f "$log" ]]; then
        offset=$(wc -c < "$log" | tr -d ' ')
    fi
    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    printf -v "$__pidvar" '%s' ""
    STOP_LOG="$log"
    STOP_LOG_OFFSET="$offset"
    for _ in $(seq 1 50); do
        if [[ -f "$log" ]] && tail -c +"$((offset + 1))" "$log" 2>/dev/null \
                | grep -q 'all connections drained\|shutting down'; then
            break
        fi
        sleep 0.1
    done
    sleep 0.2
}

# start_spiceio <kill_stale:0|1> [ENV=val ...]
# Extra assignments override the SMB/bind defaults. The first start may
# kill a leftover listener; later restarts fail instead of shooting an
# unrelated process (same rule as the cache-less NAS reader).
start_spiceio() {
    local kill_stale="$1"
    shift
    local bind_port="${BIND##*:}"
    local stale
    stale=$(lsof -i ":${bind_port}" -sTCP:LISTEN -t 2>/dev/null || true)
    if [[ -n "$stale" ]]; then
        if [[ "$kill_stale" == "1" ]]; then
            echo "[test] port ${bind_port} already in use (pid ${stale}), killing..."
            echo "$stale" | xargs kill 2>/dev/null || true
            sleep 1
        else
            echo "  FAIL: ${BIND} still in use (pid ${stale}) after stopping spiceio; not killing an unverified process"
            FAIL=$((FAIL + 1))
            exit 1
        fi
    fi
    env \
        SPICEIO_BIND="$BIND" \
        SPICEIO_SMB_SERVER="$SMB_SERVER" \
        SPICEIO_SMB_PORT="$SMB_PORT" \
        SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
        SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
        SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
        SPICEIO_SMB_SHARE="$SMB_SHARE" \
        SPICEIO_BUCKET="$BUCKET" \
        SPICEIO_REGION="$REGION" \
        SPICEIO_LOG_FILE="${SPICEIO_LOG_FILE:-}" \
        "$@" \
        "$SPICEIO_BIN" > >(tee -a "$SPICEIO_STDERR") 2> >(tee -a "$SPICEIO_STDERR" >&2) &
    SPICEIO_PID=$!
    echo "[test] waiting for spiceio on ${BIND}..."
    local i
    for i in $(seq 1 60); do
        if curl -sf -o /dev/null "${ENDPOINT}/" 2>/dev/null \
            && $AWS s3 ls 2>/dev/null | grep -q "$BUCKET"; then
            echo "[test] spiceio ready"
            return 0
        fi
        if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
            echo "[test] spiceio exited unexpectedly"
            exit 1
        fi
        sleep 0.5
    done
    echo "[test] spiceio not ready after 30s"
    exit 1
}

# Reclaim spiceio-test-* trees left by interrupted runs. Only prefixes whose
# newest object is older than STALE_TEST_PREFIX_HOURS (default 2) are removed,
# so a concurrent live run's unique token is left alone.
sweep_stale_test_prefixes() {
    local hours="${STALE_TEST_PREFIX_HOURS:-2}"
    echo "[test] sweeping spiceio-test-* prefixes older than ${hours}h"
    if nas_mount_ready; then
        local cutoff_mmin=$((hours * 60))
        find "$SMB_MOUNT" -maxdepth 1 -mindepth 1 -type d -name 'spiceio-test-*' \
            ! -name "$TEST_PREFIX" -mmin "+${cutoff_mmin}" -print \
            | while IFS= read -r dir; do
                echo "[test] removing stale ${dir}"
                rm -rf "$dir"
            done
        return 0
    fi
    python3 - "$ENDPOINT" "$BUCKET" "$hours" "$TEST_PREFIX" <<'PY'
import sys
import runpy
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

endpoint, bucket, hours, keep = sys.argv[1:5]
cutoff = datetime.now(timezone.utc) - timedelta(hours=int(hours))
api = runpy.run_path("scripts/sccache")
client = api["S3"](endpoint, bucket)
ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
deleted = 0
try:
    prefixes = []
    token = None
    seen = set()
    while True:
        query = {"list-type": "2", "prefix": "spiceio-test-", "delimiter": "/", "max-keys": "1000"}
        if token:
            query["continuation-token"] = token
        root = ET.fromstring(client.request("GET", query=query))
        for common in root.findall(f"{ns}CommonPrefixes"):
            prefixes.append(common.findtext(f"{ns}Prefix", ""))
        truncated = root.findtext(f"{ns}IsTruncated")
        if truncated == "true":
            token = root.findtext(f"{ns}NextContinuationToken")
            if not token or token in seen:
                break
            seen.add(token)
        else:
            break
    keep_prefix = keep.rstrip("/") + "/"
    for prefix in prefixes:
        if not prefix or prefix == keep_prefix:
            continue
        newest = None
        keys = []
        for page in client.pages(prefix):
            for obj in page:
                keys.append(obj["key"])
                if newest is None or obj["modified"] > newest:
                    newest = obj["modified"]
        if keys and newest is not None and newest >= cutoff:
            continue
        for i in range(0, len(keys), 1000):
            client.delete(keys[i:i + 1000])
        deleted += len(keys)
        if keys:
            print(f"[test] removed stale prefix {prefix} ({len(keys)} object(s))", flush=True)
finally:
    client.close()
print(f"[test] stale sweep deleted {deleted} object(s)", flush=True)
PY
}

# Drain the writer and SHA-256-check NAS_MANIFEST. cleanup=1 also removes
# TEST_PREFIX (last pass only — an earlier pass must leave the share for
# the next spiceio start).
verify_nas_durability() {
    local label="$1"
    local cleanup="${2:-0}"

    echo ""
    echo "======================================="
    echo "[test] NAS write-back of sccache objects (${label})"
    echo "======================================="

    # Fail while the writer is still up so EXIT cleanup can AWS-rm the prefix.
    if nas_mount_requested && ! nas_mount_ready; then
        echo "  FAIL: SPICEIO_SMB_MOUNT=${SMB_MOUNT} is not a mounted smbfs volume"
        FAIL=$((FAIL + 1))
        exit 1
    fi

    sccache --stop-server 2>/dev/null || true

    if [[ -n "$SPICEIO_PID2" ]]; then
        stop_spiceio SPICEIO_PID2
    fi
    stop_spiceio SPICEIO_PID
    local writer_suffix
    writer_suffix=$(tail -c +"$((STOP_LOG_OFFSET + 1))" "$STOP_LOG" 2>/dev/null || true)

    if printf '%s' "$writer_suffix" | grep -q 'did not reach the NAS before shutdown\|were acknowledged but are lost\|journalled write(s) remain on disk'; then
        echo "  FAIL: ${label} shutdown left acknowledged writes off the NAS"
        printf '%s' "$writer_suffix" | grep -E 'did not reach the NAS before shutdown|were acknowledged but are lost|journalled write(s) remain on disk' \
            | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        exit 1
    fi
    echo "  PASS: ${label} graceful shutdown did not report lost writes"
    PASS=$((PASS + 1))

    if nas_mount_requested; then
        if ! nas_mount_ready; then
            echo "  FAIL: SPICEIO_SMB_MOUNT=${SMB_MOUNT} is not a mounted smbfs volume"
            FAIL=$((FAIL + 1))
            exit 1
        fi
        echo "[test] verifying SHA-256 on mount ${SMB_MOUNT} (${label})"
        "$NAS_BIN" verify \
            --manifest "$NAS_MANIFEST" \
            --mount "$SMB_MOUNT"
        echo "  PASS: ${label} sccache objects on ${SMB_MOUNT} match the acknowledged SHA-256"
        PASS=$((PASS + 1))
        if [[ "$cleanup" == "1" ]] && nas_mount_ready; then
            rm -rf "${SMB_MOUNT}/${TEST_PREFIX}" 2>/dev/null || true
        fi
    else
        echo "[test] SPICEIO_SMB_MOUNT unset — ${label} read-back through a cache-less instance"
        start_spiceio 0 \
            SPICEIO_WRITE_BACK=0 \
            SPICEIO_SPILL_DIR=off \
            SPICEIO_OBJECT_CACHE_BYTES=1 \
            SPICEIO_OBJECT_CACHE_ENTRIES=1 \
            SPICEIO_IMMUTABLE_OBJECTS=0
        "$NAS_BIN" verify \
            --manifest "$NAS_MANIFEST" \
            --endpoint "$ENDPOINT" \
            --bucket "$BUCKET"
        echo "  PASS: ${label} sccache objects on the NAS match the acknowledged SHA-256"
        PASS=$((PASS + 1))
        if [[ "$cleanup" == "1" ]]; then
            $AWS s3 rm "s3://${BUCKET}/${TEST_PREFIX}/" --recursive 2>/dev/null || true
        fi
        stop_spiceio SPICEIO_PID
    fi
}

# ── Start spiceio ───────────────────────────────────────────────────────────

echo "[test] starting spiceio -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"
# Pin etag-revalidated so an ambient SPICEIO_IMMUTABLE_OBJECTS (launchd / shell)
# cannot silently skip the default path. The immutable variant is a later pass.
start_spiceio 1 SPICEIO_SMB_CONNECTIONS=128 SPICEIO_IMMUTABLE_OBJECTS=0
sweep_stale_test_prefixes

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
# Surface AWS CLI errors on the very first call so we don't fly blind under set -e.
BUCKETS=""
LB_ERR=""
for attempt in 1 2 3; do
    if BUCKETS=$($AWS s3 ls 2>&1); then
        break
    fi
    LB_ERR="$BUCKETS"
    echo "  [s3] ListBuckets attempt ${attempt}/3 failed: ${LB_ERR}"
    sleep 1
done
if [[ -z "$BUCKETS" && -n "$LB_ERR" ]]; then
    echo "  FAIL: ListBuckets never succeeded — last error: ${LB_ERR}"
    FAIL=$((FAIL + 1))
fi
assert_contains "ListBuckets contains bucket" "$BUCKET" "$BUCKETS"

# ── HeadBucket ──────────────────────────────────────────────────────────────

echo ""
echo "[s3] HeadBucket"
assert_ok "HeadBucket on existing bucket" $AWS s3api head-bucket --bucket "$BUCKET"

# ── PutObject + GetObject (small) ───────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (small)"
echo "hello spiceio" > "${TEST_WORK}/small.txt"
$AWS s3 cp "${TEST_WORK}/small.txt" "s3://${BUCKET}/${TEST_PREFIX}/small.txt" --quiet 2>/dev/null
GOT=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" - 2>/dev/null)
assert_eq "small file round-trip" "hello spiceio" "$GOT"

# ── PutObject + GetObject (64KB) ────────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (64KB)"
dd if=/dev/urandom of="${TEST_WORK}/64k.bin" bs=1024 count=64 2>/dev/null
$AWS s3 cp "${TEST_WORK}/64k.bin" "s3://${BUCKET}/${TEST_PREFIX}/64k.bin" --quiet 2>/dev/null
$AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/64k.bin" "${TEST_WORK}/64k-dl.bin" --quiet 2>/dev/null
ORIG_MD5=$(md5 -q "${TEST_WORK}/64k.bin")
DL_MD5=$(md5 -q "${TEST_WORK}/64k-dl.bin")
assert_eq "64KB file integrity" "$ORIG_MD5" "$DL_MD5"

# ── PutObject + GetObject (1MB) ─────────────────────────────────────────────

echo ""
echo "[s3] PutObject / GetObject (1MB)"
dd if=/dev/urandom of="${TEST_WORK}/1m.bin" bs=1024 count=1024 2>/dev/null
$AWS s3 cp "${TEST_WORK}/1m.bin" "s3://${BUCKET}/${TEST_PREFIX}/1m.bin" --quiet 2>/dev/null
$AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/1m.bin" "${TEST_WORK}/1m-dl.bin" --quiet 2>/dev/null
ORIG_MD5=$(md5 -q "${TEST_WORK}/1m.bin")
DL_MD5=$(md5 -q "${TEST_WORK}/1m-dl.bin")
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
# Port auto-increment test
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "======================================="
echo "[test] port auto-increment test"
echo "======================================="

# Start a second instance requesting the same bind address.
# It should auto-increment to the next port.
SPICEIO_LOG2=$(mktemp "${TEST_WORK}/log2.XXXXXX")

SPICEIO_BIND="$BIND" \
SPICEIO_SMB_SERVER="$SMB_SERVER" \
SPICEIO_SMB_PORT="$SMB_PORT" \
SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
SPICEIO_SMB_SHARE="$SMB_SHARE" \
SPICEIO_BUCKET="$BUCKET" \
SPICEIO_REGION="$REGION" \
SPICEIO_SMB_CONNECTIONS=128 \
SPICEIO_LOG_FILE="$SPICEIO_LOG2" \
"$SPICEIO_BIN" 2> >(tee -a "$SPICEIO_STDERR" >&2) &
SPICEIO_PID2=$!

echo "[test] waiting for second spiceio instance..."
ENDPOINT2=""
for i in $(seq 1 30); do
    # Wait for SMB-ready ("ready, listening on"), not merely TCP-accepting.
    ENDPOINT2=$(grep 'ready, listening on' "$SPICEIO_LOG2" 2>/dev/null | grep -o 'http://[^ ]*' | tail -1 || true)
    if [[ -n "$ENDPOINT2" ]] && curl -sf -o /dev/null "${ENDPOINT2}/" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$SPICEIO_PID2" 2>/dev/null; then
        echo "  FAIL: second spiceio exited unexpectedly"
        FAIL=$((FAIL + 1))
        SPICEIO_PID2=""
        break
    fi
    sleep 0.5
done

if [[ -n "$ENDPOINT2" ]]; then
    echo "[test] second instance at $ENDPOINT2"

    PORT1="${BIND##*:}"
    PORT2="${ENDPOINT2##*:}"
    if [[ "$PORT2" =~ ^[0-9]+$ ]] && (( PORT2 > PORT1 && PORT2 <= PORT1 + 100 )); then
        echo "  PASS: port auto-incremented ($PORT1 -> $PORT2)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: port should differ from $PORT1 and be within auto-increment range (got $PORT2)"
        FAIL=$((FAIL + 1))
    fi

    # Both instances should serve requests
    assert_ok "first instance health check" curl -sf -o /dev/null "${ENDPOINT}/"
    assert_ok "second instance health check" curl -sf -o /dev/null "${ENDPOINT2}/"

    # Both should serve S3 operations (same SMB share)
    GOT1=$($AWS s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" - 2>/dev/null || echo "FAIL")
    assert_eq "first instance S3 read" "version2" "$GOT1"

    AWS2="aws --endpoint-url $ENDPOINT2 --no-sign-request"
    GOT2=$($AWS2 s3 cp "s3://${BUCKET}/${TEST_PREFIX}/small.txt" - 2>/dev/null || echo "FAIL")
    assert_eq "second instance S3 read" "version2" "$GOT2"
else
    echo "  FAIL: second instance did not start"
    FAIL=$((FAIL + 1))
fi

# Stop the second instance
if [[ -n "$SPICEIO_PID2" ]]; then
    kill "$SPICEIO_PID2" 2>/dev/null || true
    wait "$SPICEIO_PID2" 2>/dev/null || true
    SPICEIO_PID2=""
fi
rm -f "$SPICEIO_LOG2"

echo ""
echo "======================================="
echo "[test] port auto-increment complete"
echo "[test] cumulative assertions: $PASS passed, $FAIL failed"
echo "======================================="

if [[ "$FAIL" -gt 0 ]]; then
    echo "[test] ABORTING — port auto-increment test failed"
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

# Neutralize any ambient sccache backend config so this test exercises spiceio's
# S3 endpoint, not a leaked local-disk/other cache. sccache prefers SCCACHE_DIR
# (local disk) over SCCACHE_BUCKET when both are set, so an inherited
# SCCACHE_DIR (e.g. from another project's build env) would silently bypass
# spiceio entirely.
unset SCCACHE_DIR SCCACHE_GCS_BUCKET SCCACHE_AZURE_CONNECTION_STRING \
    SCCACHE_REDIS SCCACHE_MEMCACHED SCCACHE_WEBDAV_ENDPOINT 2>/dev/null || true

# Also drop the ambient *S3 credential mode*. A developer whose shell already
# points sccache at a running spiceio sets SCCACHE_S3_NO_CREDENTIALS=1, which
# directly contradicts the anonymous-but-present credentials this test exports
# below — sccache 0.17 refuses the combination outright ("If setting S3
# credentials, SCCACHE_S3_NO_CREDENTIALS must not be set") and `--start-server`
# fails. AWS_PROFILE goes for the same reason: it would put a real credential
# chain ahead of the test's, against an endpoint that authenticates nothing.
unset SCCACHE_S3_NO_CREDENTIALS AWS_PROFILE 2>/dev/null || true

export SCCACHE_BUCKET="$BUCKET"
export SCCACHE_ENDPOINT="$ENDPOINT"
export SCCACHE_REGION="$REGION"
export SCCACHE_S3_USE_SSL=false
export SCCACHE_S3_KEY_PREFIX="$SCCACHE_PREFIX"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0  # sccache cannot cache incremental builds

sccache --start-server
sccache --zero-stats 2>/dev/null || true

# ── Client-side metrics ─────────────────────────────────────────────────────
#
# sccache's own JSON stats are the client's view of how fast this backend is:
# `cache_read_hit_duration` and `cache_write_duration` are cumulative, so the
# per-op averages below are what stay comparable between a cold and a warm
# build (and between runs with different unit counts). Printed as `[metrics]`
# lines so CI logs carry a time series even when the run passes.
sccache_metrics() {
    # Averages are computed in named locals rather than inline in the f-strings:
    # a backslash-escaped quote inside an f-string expression is a Python syntax
    # error, and the failure is invisible here — it just prints zeros, which
    # read as "the cache did nothing" instead of "the metrics broke".
    sccache --show-stats --stats-format json 2>/dev/null | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)["stats"]
except Exception:
    print("0 0 0 0 0 0 0.00 0.00"); raise SystemExit
def total(field):
    v = doc.get(field) or {}
    counts = v.get("counts") if isinstance(v, dict) else None
    return sum(counts.values()) if counts else 0
def dur_ms(field):
    d = doc.get(field) or {}
    return d.get("secs", 0) * 1000.0 + d.get("nanos", 0) / 1e6
hits, misses = total("cache_hits"), total("cache_misses")
writes = doc.get("cache_writes", 0)
hit_avg = dur_ms("cache_read_hit_duration") / hits if hits else 0.0
write_avg = dur_ms("cache_write_duration") / writes if writes else 0.0
print(hits, misses, writes,
      doc.get("cache_read_errors", 0), doc.get("cache_write_errors", 0),
      doc.get("cache_timeouts", 0),
      f"{hit_avg:.2f}", f"{write_avg:.2f}")
' || echo "0 0 0 0 0 0 0.00 0.00"
}

report_metrics() {
    local phase="$1" secs="$2"
    local hits misses writes rerr werr touts hitavg wravg
    read -r hits misses writes rerr werr touts hitavg wravg < <(sccache_metrics)
    echo "[metrics] ${phase} wall=${secs}s hits=${hits} misses=${misses} writes=${writes} \
read_err=${rerr} write_err=${werr} timeouts=${touts} \
hit_avg=${hitavg}ms write_avg=${wravg}ms"
}

echo ""
echo "[test] === cold build (populating cache) ==="
rm -rf "$TEST_TARGET_DIR"
COLD_START=$(date +%s)
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1
COLD_SECS=$(( $(date +%s) - COLD_START ))
report_metrics cold "$COLD_SECS"

sccache --zero-stats 2>/dev/null || true

echo ""
echo "[test] === warm build (should hit cache) ==="
rm -rf "$TEST_TARGET_DIR"
WARM_START=$(date +%s)
CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1
WARM_SECS=$(( $(date +%s) - WARM_START ))
report_metrics warm "$WARM_SECS"

echo ""
echo "======================================="
echo "[test] sccache stats:"
echo "======================================="
sccache --show-stats
echo "======================================="

# ── Verify cache hits ───────────────────────────────────────────────
#
# Asserts the *same* gate CI uses: hits > 0 and write errors == 0 on the warm
# build. One automatic retry of the warm build absorbs a single shared-NAS
# blip (common under concurrent CI runners) without loosening the final bar.

check_warm_stats() {
    local stats hits write_err read_err timeouts
    stats=$(sccache --show-stats 2>&1)
    hits=$(echo "$stats" | grep -m1 "^Cache hits" | awk '{print $NF}' || echo "0")
    write_err=$(echo "$stats" | grep -m1 "Cache write errors" | awk '{print $NF}' || echo "0")
    # A read error or timeout on a warm build is a cache the client could not
    # use — the same class of failure as a failed write, and equally invisible
    # to a build that still succeeds by recompiling. Checked here so the
    # existing retry absorbs a single shared-NAS blip.
    read_err=$(echo "$stats" | grep -m1 "Cache read errors" | awk '{print $NF}' || echo "0")
    timeouts=$(echo "$stats" | grep -m1 "Cache timeouts" | awk '{print $NF}' || echo "0")
    CACHE_HITS=${hits:-0}
    WRITE_ERRORS=${write_err:-0}
    READ_ERRORS=${read_err:-0}
    CACHE_TIMEOUTS=${timeouts:-0}
    [[ "$CACHE_HITS" -gt 0 && "$WRITE_ERRORS" -eq 0 \
        && "$READ_ERRORS" -eq 0 && "$CACHE_TIMEOUTS" -eq 0 ]]
}

verify_warm_or_retry() {
    local attempt=1
    local max_attempts=2
    while true; do
        if check_warm_stats; then
            echo "[test] PASS: ${SCCACHE_MODE:-sccache} warm build got $CACHE_HITS cache hits, 0 read/write errors, 0 timeouts"
            PASS=$((PASS + 1))
            return 0
        fi
        echo "[test] warm-build stats attempt ${attempt}/${max_attempts}: hits=${CACHE_HITS} write_errors=${WRITE_ERRORS} read_errors=${READ_ERRORS} timeouts=${CACHE_TIMEOUTS}"
        if [[ "$attempt" -ge "$max_attempts" ]]; then
            break
        fi
        echo "[test] retrying warm build once (shared NAS can flake one write under load)..."
        sccache --zero-stats 2>/dev/null || true
        rm -rf "$TEST_TARGET_DIR"
        CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1
        attempt=$((attempt + 1))
    done

    # Split the conditions so a hits-ok / writes-bad failure is obvious.
    echo ""
    if [[ "${CACHE_HITS:-0}" -le 0 ]]; then
        echo "[test] FAIL: expected cache hits > 0 (got ${CACHE_HITS:-0})"
    fi
    if [[ "${WRITE_ERRORS:-0}" -ne 0 ]]; then
        echo "[test] FAIL: expected cache write errors == 0 (got ${WRITE_ERRORS:-0})"
        echo "[test]       (hits were ${CACHE_HITS:-0} — cache is partially working;"
        echo "[test]        write errors usually mean transient NAS/SMB overload during PUT)"
    fi
    if [[ "${READ_ERRORS:-0}" -ne 0 ]]; then
        echo "[test] FAIL: expected cache read errors == 0 (got ${READ_ERRORS:-0})"
        echo "[test]       (a GET that sccache could not use — the build still"
        echo "[test]        succeeds by recompiling, so only this check catches it)"
    fi
    if [[ "${CACHE_TIMEOUTS:-0}" -ne 0 ]]; then
        echo "[test] FAIL: expected cache timeouts == 0 (got ${CACHE_TIMEOUTS:-0})"
    fi
    if [[ -s "${SPICEIO_LOG_FILE:-}" ]]; then
        echo "[test] last 40 lines of SPICEIO_LOG_FILE (${SPICEIO_LOG_FILE}):"
        tail -40 "$SPICEIO_LOG_FILE" || true
    elif [[ -s "$SPICEIO_STDERR" ]]; then
        echo "[test] last 40 lines of spiceio stderr capture:"
        tail -40 "$SPICEIO_STDERR" || true
    fi
    exit 1
}

run_sccache_builds() {
    local mode="$1"
    SCCACHE_MODE="$mode"
    echo ""
    echo "[test] === ${mode} cold build (populating cache) ==="
    rm -rf "$TEST_TARGET_DIR"
    local cold_start
    cold_start=$(date +%s)
    CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1
    report_metrics "${mode}-cold" "$(( $(date +%s) - cold_start ))"

    sccache --zero-stats 2>/dev/null || true

    echo ""
    echo "[test] === ${mode} warm build (should hit cache) ==="
    rm -rf "$TEST_TARGET_DIR"
    local warm_start
    warm_start=$(date +%s)
    CARGO_TARGET_DIR="$TEST_TARGET_DIR" cargo build 2>&1
    report_metrics "${mode}-warm" "$(( $(date +%s) - warm_start ))"

    echo ""
    echo "======================================="
    echo "[test] ${mode} sccache stats:"
    echo "======================================="
    sccache --show-stats
    echo "======================================="
    echo ""
    verify_warm_or_retry
}

snapshot_sccache_objects() {
    local mode="$1"
    echo ""
    echo "======================================="
    echo "[test] snapshot sccache objects for NAS verify (${mode})"
    echo "======================================="
    if [[ ! -x "$NAS_BIN" ]]; then
        echo "[test] FAIL: ${NAS_BIN} not built — cargo build --features loadgen --bins"
        FAIL=$((FAIL + 1))
        exit 1
    fi
    "$NAS_BIN" snapshot \
        --endpoint "$ENDPOINT" \
        --bucket "$BUCKET" \
        --prefix "$SCCACHE_PREFIX" \
        --out "$NAS_MANIFEST"
    echo "  PASS: recorded SHA-256 of ${mode} sccache objects under ${SCCACHE_PREFIX}"
    PASS=$((PASS + 1))
}

run_sccache_builds "etag-revalidated"
snapshot_sccache_objects "etag-revalidated"

# ════════════════════════════════════════════════════════════════════════════
# Concurrent load burst
# ════════════════════════════════════════════════════════════════════════════
#
# A cargo build of this crate is ~30 compile units — nowhere near the request
# concurrency a real sccache fleet produces, so the build test above can pass
# while the proxy falls over under a stampede. This drives the same request
# shape at high concurrency over persistent connections and requires that every
# request succeed. Metrics are printed either way so CI logs carry a throughput
# series alongside the pass/fail.
#
# Uses the debug loadgen that `make build` (--all-features) already produces;
# skipped if it is absent so the suite still runs from a bare `cargo build`.

LOADGEN="./target/debug/spiceio-loadgen"
BURST_CONCURRENCY="${SCCACHE_TEST_BURST_CONCURRENCY:-64}"
BURST_OBJECTS="${SCCACHE_TEST_BURST_OBJECTS:-128}"
# Failure budget, as a percentage of attempted requests. Zero, deliberately.
#
# An earlier revision carried a 2% budget because spiceio intermittently dropped
# large writes under burst load (3.3% of PUTs during a 1163-unit sccache build).
# That is fixed, so the budget is gone: every failure here is now a regression.
#
# `errors` counts what it needs to for that to mean anything. The load generator
# classifies each response against the status its *operation* expects — a PUT or
# a cache-hit read answered 404 is a failure, 404 is a success only for a miss
# probe, and 5xx never passes — so a proxy that silently stores nothing can no
# longer post a clean run. It is left overridable only for bisecting against an
# older build.
BURST_MAX_ERROR_PCT="${SCCACHE_TEST_BURST_MAX_ERROR_PCT:-0}"

if [[ -x "$LOADGEN" ]]; then
    echo ""
    echo "======================================="
    echo "[test] concurrent load burst (c=${BURST_CONCURRENCY}, ${BURST_OBJECTS} objects)"
    echo "======================================="
    BURST_JSON="${SPICEIO_STDERR}.burst.json"
    # Exit status is ignored here: the loadgen exits nonzero on any error at
    # all, and the budget below is the actual gate.
    "$LOADGEN" \
        --endpoint "$ENDPOINT" \
        --bucket "$BUCKET" \
        --prefix "${TEST_PREFIX}/burst" \
        --concurrency "$BURST_CONCURRENCY" \
        --objects "$BURST_OBJECTS" \
        --ops $((BURST_OBJECTS * 4)) \
        --phase put,get,get-miss,head-hit,head-miss,mixed \
        --json "$BURST_JSON" || true

    if [[ -s "$BURST_JSON" ]]; then
        BURST_TOTALS=$(python3 - "$BURST_JSON" <<'PY'
import json, sys
with open(sys.argv[1]) as fh:
    doc = json.load(fh)
ops = errs = 0
for p in doc["phases"]:
    lat = p["latency_us"]
    e = sum(p["errors"].values()) if p["errors"] else 0
    ops += p["ops"] + e   # p["ops"] counts completions only
    errs += e
    # No status allowlist here: which statuses are acceptable depends on the
    # operation, and that judgement already happened in the load generator
    # (Op::accepts), which turned every mismatch into a named entry in
    # `errors` — e.g. "PUT status 404". Re-deciding it here with a flat
    # allowlist is exactly how a failed write got counted as a success before.
    detail = " ".join(f"{k}={v}" for k, v in sorted(p["errors"].items())) if p["errors"] else ""
    statuses = " ".join(f"{k}x{v}" for k, v in sorted(p["statuses"].items()))
    print(f"[metrics] burst phase={p['phase']} c={p['concurrency']} "
          f"ops={p['ops']} ops_s={p['ops_per_sec']:.1f} mib_s={p['mib_per_sec']:.1f} "
          f"p99={lat['p99']/1000:.2f}ms p99.9={lat['p999']/1000:.2f}ms "
          f"max={lat['max']/1000:.2f}ms errors={e} status=[{statuses}]"
          + (f" failed=[{detail}]" if detail else ""), file=sys.stderr)
print(ops, errs)
PY
)
        BURST_OPS=$(echo "$BURST_TOTALS" | awk '{print $1}')
        BURST_ERRS=$(echo "$BURST_TOTALS" | awk '{print $2}')
        BURST_PCT=$(awk -v e="${BURST_ERRS:-0}" -v o="${BURST_OPS:-1}" \
            'BEGIN{printf "%.2f", (o>0? 100*e/o : 0)}')
        echo "[metrics] burst total ops=${BURST_OPS} errors=${BURST_ERRS} (${BURST_PCT}%)"
        if awk -v p="$BURST_PCT" -v m="$BURST_MAX_ERROR_PCT" 'BEGIN{exit !(p<=m)}'; then
            if [[ "${BURST_ERRS:-0}" -gt 0 ]]; then
                echo "  PASS: load burst error rate ${BURST_PCT}% within ${BURST_MAX_ERROR_PCT}% budget"
                echo "  NOTE: ${BURST_ERRS} request(s) failed — the budget is only non-zero"
                echo "        when overridden; see the [metrics] failed=[...] breakdown above"
            else
                echo "  PASS: load burst completed with no failed requests"
            fi
            PASS=$((PASS + 1))
        else
            echo "  FAIL: ${BURST_ERRS} of ${BURST_OPS} burst requests failed (${BURST_PCT}%)"
            echo "        A wrong status counts here: a PUT or a cache-hit read"
            echo "        answered 404 means the object was never stored."
            FAIL=$((FAIL + 1))
        fi
    else
        echo "  FAIL: load burst produced no results"
        FAIL=$((FAIL + 1))
    fi

    # Remove the burst objects; the AWS-CLI section's cleanup only covers the
    # keys it wrote itself.
    "$LOADGEN" --endpoint "$ENDPOINT" --bucket "$BUCKET" \
        --prefix "${TEST_PREFIX}/burst" --concurrency 16 \
        --objects "$BURST_OBJECTS" --ops "$BURST_OBJECTS" \
        --phase delete >/dev/null 2>&1 || true
    rm -f "$BURST_JSON"
else
    echo ""
    echo "[test] NOTE: ${LOADGEN} not built — skipping concurrent load burst"
    echo "[test]       (build it with: cargo build --all-targets --all-features)"
fi

if [[ "$FAIL" -gt 0 ]]; then
    echo "[test] ABORTING — concurrent load burst failed"
    exit 1
fi

# ── Session backoff exercise verification ───────────────────────────────────
# (with SPICEIO_SMB_CONNECTIONS=128 on startup)
if grep -q -i 'capacity\|reduced from\|too many sessions\|0xC00000C[ED]' "$SPICEIO_STDERR" 2>/dev/null; then
    echo "  PASS: session backoff (capacity reduction) messages seen in spiceio logs"
    PASS=$((PASS + 1))
else
    echo "  NOTE: no capacity reduction messages in sccache test (server allowed 128 conns)"
fi

# Exercise retention through the running test instance. Restrict this CI call
# to the test's own namespace; make test-sccache-clean can target a live cache.
SCCACHE_ENDPOINT="$ENDPOINT" SCCACHE_BUCKET="$BUCKET" \
    SCCACHE_S3_KEY_PREFIX="$TEST_PREFIX/retention" \
    ./scripts/test-sccache-clean.py

# ── NAS durability (etag-revalidated), then the immutable-objects variant ──
#
# Write-back acknowledges PutObject from memory. Warm-build hits can succeed
# without the bodies ever reaching the share. Drain, SHA-256 the same keys
# on the NAS, then repeat under SPICEIO_IMMUTABLE_OBJECTS=1 (sccache
# production: hits with no backend round trip; existence index on).

verify_nas_durability "etag-revalidated" 0

echo ""
echo "======================================="
echo "[test] sccache integration (immutable objects)"
echo "======================================="
start_spiceio 0 \
    SPICEIO_SMB_CONNECTIONS=128 \
    SPICEIO_IMMUTABLE_OBJECTS=1
# slog! (stdout) and serr! both land in SPICEIO_STDERR; give tee a tick to flush.
sleep 0.2
if ! grep -q 'immutable keys (hits served with no backend round trip)' "$SPICEIO_STDERR"; then
    echo "  FAIL: spiceio did not log immutable-key cache mode"
    FAIL=$((FAIL + 1))
    exit 1
fi
echo "  PASS: spiceio enabled immutable-key cache (no backend round trip on hit)"
PASS=$((PASS + 1))
if ! grep -q 'existence index: on' "$SPICEIO_STDERR"; then
    echo "  FAIL: immutable mode did not enable the existence index"
    FAIL=$((FAIL + 1))
    exit 1
fi
echo "  PASS: existence index on with immutable objects"
PASS=$((PASS + 1))

sccache --stop-server 2>/dev/null || true
SCCACHE_PREFIX="${TEST_PREFIX}/sccache-immutable"
export SCCACHE_S3_KEY_PREFIX="$SCCACHE_PREFIX"
NAS_MANIFEST="${TEST_WORK}/sccache-nas-immutable.json"
sccache --start-server
sccache --zero-stats 2>/dev/null || true

run_sccache_builds "immutable"
snapshot_sccache_objects "immutable"

# Immutable hits are served with no SMB open; the response must say so.
IMMUTABLE_KEY=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["objects"][0]["key"])' "$NAS_MANIFEST")
IMMUTABLE_HEADERS=$(mktemp "${TEST_WORK}/headers.XXXXXX")
curl -sD "$IMMUTABLE_HEADERS" -o /dev/null "${ENDPOINT}/${BUCKET}/${IMMUTABLE_KEY}"
if grep -qi '^x-spiceio-cache: HIT' "$IMMUTABLE_HEADERS"; then
    echo "  PASS: immutable GET of a snapshotted key is x-spiceio-cache: HIT"
    PASS=$((PASS + 1))
else
    echo "  FAIL: immutable GET of ${IMMUTABLE_KEY} was not a cache HIT"
    sed 's/^/    /' "$IMMUTABLE_HEADERS" | head -20
    FAIL=$((FAIL + 1))
    exit 1
fi

verify_nas_durability "immutable" 1

# ── Stderr guard ────────────────────────────────────────────────────────────
#
# Any `[spiceio] error:` line means a code path is leaking through the
# generic 500 InternalError arm of `io_to_s3_error`. Expected transients
# (NotFound on HEAD probes, sharing violations, etc.) are mapped to typed
# `io::ErrorKind`s and logged via `slog!` without the "error:" prefix.

# Both spiceio instances are already stopped (and PIDs cleared) so the EXIT
# trap's kills are no-ops. Sleep so tee in <(...) finishes flushing.
sleep 0.2

if [[ -s "$SPICEIO_STDERR" ]] && grep -q '\[spiceio\] error:' "$SPICEIO_STDERR"; then
    echo ""
    echo "[test] FAIL: spiceio emitted unexpected error log lines:"
    grep '\[spiceio\] error:' "$SPICEIO_STDERR" | head -20
    exit 1
fi
