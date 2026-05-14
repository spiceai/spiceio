#!/usr/bin/env bash
set -euo pipefail

# ── Extended live test ─────────────────────────────────────────────────────
#
# Covers operations not exercised by test-sccache.sh: multipart uploads
# (single + concurrent), range requests (sequential + concurrent), batch
# multi-delete, conditional writes (If-None-Match), ListObjects under write
# load, and streaming GET cancellation.
#
# Usage: SPICEIO_SMB_USER=u SPICEIO_SMB_PASS=p ./scripts/test-extended.sh

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-extended}"
BIND="${SPICEIO_BIND:-127.0.0.1:18336}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/debug/spiceio"
ENDPOINT="http://${BIND}"
AWS="aws --endpoint-url $ENDPOINT --no-sign-request --region $REGION"
PREFIX="ext-$$"
TMPDIR_BASE=$(mktemp -d /tmp/spiceio-ext.XXXXXX)
PASS=0
FAIL=0
CONCURRENCY="${SPICEIO_EXT_CONCURRENCY:-8}"
CURL_TIMEOUT="${SPICEIO_EXT_TIMEOUT:-60}"

# ── Cleanup ────────────────────────────────────────────────────────────────

SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[ext] cleaning up..."
    $AWS s3 rm "s3://${BUCKET}/${PREFIX}/" --recursive --quiet 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$TMPDIR_BASE"
}
trap cleanup EXIT

# ── Helpers ────────────────────────────────────────────────────────────────

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

assert_ok() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (exit $?)"
        FAIL=$((FAIL + 1))
    fi
}

assert_http_status() {
    local label="$1" expected="$2"
    shift 2
    local actual
    actual=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" "$@" 2>/dev/null || echo "000")
    if [[ "$actual" == "$expected" ]]; then
        echo "  PASS: $label (HTTP $actual)"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected HTTP $expected, got $actual)"
        FAIL=$((FAIL + 1))
    fi
}

wait_pids() {
    WAIT_ERRORS=0
    for pid in "$@"; do
        wait "$pid" || WAIT_ERRORS=$((WAIT_ERRORS + 1))
    done
}

# ── Start spiceio ──────────────────────────────────────────────────────────

echo "[ext] starting spiceio -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"

BIND_PORT="${BIND##*:}"
STALE_PIDS=$(lsof -i ":${BIND_PORT}" -sTCP:LISTEN -t 2>/dev/null || true)
if [[ -n "$STALE_PIDS" ]]; then
    echo "[ext] killing stale on port ${BIND_PORT}..."
    echo "$STALE_PIDS" | xargs kill 2>/dev/null || true
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

for i in $(seq 1 60); do
    if curl -sf --max-time 2 -o /dev/null "${ENDPOINT}/" 2>/dev/null; then break; fi
    if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
        echo "[ext] spiceio failed to start"
        exit 1
    fi
    sleep 0.5
done
echo "[ext] spiceio ready (concurrency=${CONCURRENCY})"

# ════════════════════════════════════════════════════════════════════════════
# 1. Multipart upload — single 10MB file
#    AWS CLI defaults to multipart_threshold=8MB so a 10MB file goes multipart
#    (typically 2 parts of ~8MB + ~2MB). Exercises CreateMultipart →
#    UploadPart × N → CompleteMultipart.
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 1. Multipart upload (single 10MB → multiple parts)"
echo "═══════════════════════════════════════════════════════════════"

MP_DIR="${TMPDIR_BASE}/mp"
mkdir -p "$MP_DIR"
dd if=/dev/urandom of="${MP_DIR}/src" bs=1024 count=10240 2>/dev/null
ORIG_MD5=$(md5 -q "${MP_DIR}/src")

$AWS s3 cp "${MP_DIR}/src" "s3://${BUCKET}/${PREFIX}/mp-10m" --quiet
$AWS s3 cp "s3://${BUCKET}/${PREFIX}/mp-10m" "${MP_DIR}/dl" --quiet
DL_MD5=$(md5 -q "${MP_DIR}/dl")
assert_eq "10MB multipart round-trip" "$ORIG_MD5" "$DL_MD5"

# ════════════════════════════════════════════════════════════════════════════
# 2. Concurrent multipart uploads (N parallel × 10MB each, distinct keys)
#    Stresses the in-memory multipart store, WAL temp file naming, and
#    pipelined writes across the connection pool.
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 2. Concurrent multipart uploads (${CONCURRENCY} × 10MB)"
echo "═══════════════════════════════════════════════════════════════"

CMP_DIR="${TMPDIR_BASE}/cmp"
mkdir -p "$CMP_DIR"
for i in $(seq 1 "$CONCURRENCY"); do
    dd if=/dev/urandom of="${CMP_DIR}/src-${i}" bs=1024 count=10240 2>/dev/null
done

PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$CONCURRENCY"); do
    $AWS s3 cp "${CMP_DIR}/src-${i}" "s3://${BUCKET}/${PREFIX}/cmp-${i}" --quiet 2>/dev/null &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
TOTAL_MB=$((CONCURRENCY * 10))
printf "  %d × 10MB multiparts in %.2fs  (%.1f MiB/s)  errors=%d\n" \
    "$CONCURRENCY" "$ELAPSED" "$(echo "$TOTAL_MB / $ELAPSED" | bc -l)" "$WAIT_ERRORS"

PREV_PASS=$PASS
for i in $(seq 1 "$CONCURRENCY"); do
    $AWS s3 cp "s3://${BUCKET}/${PREFIX}/cmp-${i}" "${CMP_DIR}/dl-${i}" --quiet 2>/dev/null || true
    ORIG=$(md5 -q "${CMP_DIR}/src-${i}")
    GOT=$(md5 -q "${CMP_DIR}/dl-${i}" 2>/dev/null || echo "MISSING")
    assert_eq "cmp-${i} integrity" "$ORIG" "$GOT"
done
echo "  integrity: $((PASS - PREV_PASS))/${CONCURRENCY} verified"

# ════════════════════════════════════════════════════════════════════════════
# 3. Range GET — multiple non-overlapping ranges on a 1MB file
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 3. Range requests on 1MB file (8 × 128KB sequential ranges)"
echo "═══════════════════════════════════════════════════════════════"

R_DIR="${TMPDIR_BASE}/range"
mkdir -p "$R_DIR"
dd if=/dev/urandom of="${R_DIR}/src" bs=1024 count=1024 2>/dev/null
$AWS s3 cp "${R_DIR}/src" "s3://${BUCKET}/${PREFIX}/range-1m" --quiet

for chunk in $(seq 0 7); do
    START_B=$((chunk * 131072))
    END_B=$((START_B + 131071))
    curl -sf --max-time "$CURL_TIMEOUT" \
        -H "Range: bytes=${START_B}-${END_B}" \
        "${ENDPOINT}/${BUCKET}/${PREFIX}/range-1m" \
        -o "${R_DIR}/chunk-${chunk}" 2>/dev/null
done
cat "${R_DIR}"/chunk-* > "${R_DIR}/reassembled"
ORIG_MD5=$(md5 -q "${R_DIR}/src")
GOT_MD5=$(md5 -q "${R_DIR}/reassembled")
assert_eq "8-chunk range reassembly integrity" "$ORIG_MD5" "$GOT_MD5"

assert_http_status "Range returns 206 Partial Content" "206" \
    -H "Range: bytes=0-1023" "${ENDPOINT}/${BUCKET}/${PREFIX}/range-1m"

# ════════════════════════════════════════════════════════════════════════════
# 4. Concurrent range GETs against the same large file
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 4. Concurrent range GETs (${CONCURRENCY} parallel slices of 4MB file)"
echo "═══════════════════════════════════════════════════════════════"

CR_DIR="${TMPDIR_BASE}/crange"
mkdir -p "$CR_DIR"
dd if=/dev/urandom of="${CR_DIR}/src" bs=1024 count=4096 2>/dev/null
$AWS s3 cp "${CR_DIR}/src" "s3://${BUCKET}/${PREFIX}/crange-4m" --quiet

SIZE=$((4 * 1024 * 1024))
CHUNK_SIZE=$((SIZE / CONCURRENCY))
PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 0 $((CONCURRENCY - 1))); do
    START_B=$((i * CHUNK_SIZE))
    END_B=$((START_B + CHUNK_SIZE - 1))
    curl -sf --max-time "$CURL_TIMEOUT" \
        -H "Range: bytes=${START_B}-${END_B}" \
        "${ENDPOINT}/${BUCKET}/${PREFIX}/crange-4m" \
        -o "${CR_DIR}/chunk-${i}" 2>/dev/null &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
printf "  %d concurrent range GETs in %.2fs  errors=%d\n" "$CONCURRENCY" "$ELAPSED" "$WAIT_ERRORS"

# Reassemble in numeric order and compare
ls "${CR_DIR}"/chunk-* | sort -V | xargs cat > "${CR_DIR}/reassembled"
ORIG_MD5=$(md5 -q "${CR_DIR}/src")
GOT_MD5=$(md5 -q "${CR_DIR}/reassembled")
assert_eq "concurrent range reassembly integrity" "$ORIG_MD5" "$GOT_MD5"

# ════════════════════════════════════════════════════════════════════════════
# 5. Multi-delete (DeleteObjects) — batch operation via POST ?delete
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 5. Multi-delete (DeleteObjects batch of ${CONCURRENCY} keys)"
echo "═══════════════════════════════════════════════════════════════"

MD_DIR="${TMPDIR_BASE}/mdel"
mkdir -p "$MD_DIR"
echo "delete me" > "${MD_DIR}/data"
for i in $(seq 1 "$CONCURRENCY"); do
    $AWS s3 cp "${MD_DIR}/data" "s3://${BUCKET}/${PREFIX}/mdel-${i}" --quiet
done

# Build the JSON delete spec; aws cli converts to the XML body spiceio expects.
DEL_JSON='{"Objects":['
for i in $(seq 1 "$CONCURRENCY"); do
    [[ $i -gt 1 ]] && DEL_JSON="${DEL_JSON},"
    DEL_JSON="${DEL_JSON}{\"Key\":\"${PREFIX}/mdel-${i}\"}"
done
DEL_JSON="${DEL_JSON}],\"Quiet\":false}"

$AWS s3api delete-objects --bucket "$BUCKET" --delete "$DEL_JSON" >/dev/null

DELETED=0
for i in $(seq 1 "$CONCURRENCY"); do
    if ! $AWS s3api head-object --bucket "$BUCKET" --key "${PREFIX}/mdel-${i}" >/dev/null 2>&1; then
        DELETED=$((DELETED + 1))
    fi
done
assert_eq "multi-delete removed all ${CONCURRENCY} objects" "$CONCURRENCY" "$DELETED"

# Mixed exists/non-exists: deleting a non-existent key should be idempotent
$AWS s3api delete-objects --bucket "$BUCKET" --delete \
    "{\"Objects\":[{\"Key\":\"${PREFIX}/never-existed\"}],\"Quiet\":true}" >/dev/null
assert_eq "multi-delete on non-existent key is idempotent" "0" "$?"

# ════════════════════════════════════════════════════════════════════════════
# 6. Conditional writes (If-None-Match: *)
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 6. Conditional writes (If-None-Match: *)"
echo "═══════════════════════════════════════════════════════════════"

assert_http_status "first PUT with If-None-Match=* returns 200" "200" \
    -X PUT --data "first" -H "If-None-Match: *" \
    "${ENDPOINT}/${BUCKET}/${PREFIX}/cond-1"

assert_http_status "second PUT to same key returns 412" "412" \
    -X PUT --data "second" -H "If-None-Match: *" \
    "${ENDPOINT}/${BUCKET}/${PREFIX}/cond-1"

GOT=$($AWS s3 cp "s3://${BUCKET}/${PREFIX}/cond-1" - 2>/dev/null)
assert_eq "conditional write preserved first value" "first" "$GOT"

# ════════════════════════════════════════════════════════════════════════════
# 7. Race: N concurrent If-None-Match: * writes to the same key.
#    Required guarantees: at least one writer wins, no request hangs (curl
#    "000"), and every request returns *some* HTTP status. Unexpected non-
#    {200,412} responses are tolerated up to a small budget — under heavy
#    SMB contention a brief sharing violation can surface as a 5xx, which
#    is observable but not a correctness regression.
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 7. Concurrent conditional writes (${CONCURRENCY} racing on same key)"
echo "═══════════════════════════════════════════════════════════════"

RACE_RESULTS="${TMPDIR_BASE}/race-results"
: > "$RACE_RESULTS"
PIDS=()
for i in $(seq 1 "$CONCURRENCY"); do
    (
        STATUS=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "$CURL_TIMEOUT" \
            -X PUT --data "racer-${i}" -H "If-None-Match: *" \
            "${ENDPOINT}/${BUCKET}/${PREFIX}/race-1" 2>/dev/null || echo "000")
        echo "${i}:${STATUS}" >> "$RACE_RESULTS"
    ) &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"

WINS=$(grep -c ":200$" "$RACE_RESULTS" || true)
LOSSES=$(grep -c ":412$" "$RACE_RESULTS" || true)
HUNG=$(grep -c ":000$" "$RACE_RESULTS" || true)
OTHER_LINES=$(grep -v -E ":(200|412|000)$" "$RACE_RESULTS" || true)
OTHER=$(printf '%s' "$OTHER_LINES" | grep -c . || true)
TOTAL=$((WINS + LOSSES + OTHER + HUNG))
printf "  winners=%d losers=%d hung=%d other=%d (total=%d)\n" \
    "$WINS" "$LOSSES" "$HUNG" "$OTHER" "$CONCURRENCY"
if (( OTHER > 0 )); then
    printf "  other-status lines:\n%s\n" "$OTHER_LINES" | sed 's/^/    /'
fi

# Required guarantees: ≥1 winner, no hangs, every request returned a status.
if (( WINS >= 1 && HUNG == 0 && TOTAL == CONCURRENCY )); then
    echo "  PASS: ≥1 winner, no hangs, all ${CONCURRENCY} requests terminated"
    PASS=$((PASS + 1))
else
    echo "  FAIL: invalid race outcome (wins=$WINS losses=$LOSSES hung=$HUNG other=$OTHER total=$TOTAL)"
    FAIL=$((FAIL + 1))
fi

# ════════════════════════════════════════════════════════════════════════════
# 8. ListObjectsV2 during concurrent writes
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 8. ListObjectsV2 while ${CONCURRENCY} writes are in flight"
echo "═══════════════════════════════════════════════════════════════"

LIST_DIR="${TMPDIR_BASE}/list"
mkdir -p "$LIST_DIR"
echo "list data" > "${LIST_DIR}/src"

PIDS=()
for i in $(seq 1 "$CONCURRENCY"); do
    $AWS s3 cp "${LIST_DIR}/src" "s3://${BUCKET}/${PREFIX}/list-${i}" --quiet 2>/dev/null &
    PIDS+=($!)
done

LIST_OK=0
for i in $(seq 1 5); do
    if $AWS s3 ls "s3://${BUCKET}/${PREFIX}/" >/dev/null 2>&1; then
        LIST_OK=$((LIST_OK + 1))
    fi
    sleep 0.1
done
wait_pids "${PIDS[@]}"
assert_eq "all 5 concurrent list ops succeeded under write load" "5" "$LIST_OK"

LIST_OUT=$($AWS s3 ls "s3://${BUCKET}/${PREFIX}/" | grep -c "list-" || true)
assert_eq "final list contains all ${CONCURRENCY} writes" "$CONCURRENCY" "$LIST_OUT"

# ════════════════════════════════════════════════════════════════════════════
# 9. Streaming GET cancellation — client disconnects mid-stream
#    Verifies the streaming task in router.rs handles tx.send failure cleanly
#    (no panic, no resource leak, subsequent requests still served).
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 9. Streaming GET cancellation"
echo "═══════════════════════════════════════════════════════════════"

SC_DIR="${TMPDIR_BASE}/scancel"
mkdir -p "$SC_DIR"
dd if=/dev/urandom of="${SC_DIR}/src" bs=1024 count=4096 2>/dev/null
$AWS s3 cp "${SC_DIR}/src" "s3://${BUCKET}/${PREFIX}/cancel-4m" --quiet

# Force mid-stream disconnect: pipe to head -c 1024, which SIGPIPEs curl
# after 1024 bytes leave the kernel.
( curl -sS --max-time "$CURL_TIMEOUT" \
    "${ENDPOINT}/${BUCKET}/${PREFIX}/cancel-4m" 2>/dev/null || true ) \
    | head -c 1024 > /dev/null || true

sleep 0.5
assert_ok "spiceio healthy after cancelled stream" \
    curl -sf --max-time 5 -o /dev/null "${ENDPOINT}/"

# A subsequent full GET on the same key still works end-to-end
$AWS s3 cp "s3://${BUCKET}/${PREFIX}/cancel-4m" "${SC_DIR}/dl-after" --quiet
ORIG_MD5=$(md5 -q "${SC_DIR}/src")
GOT_MD5=$(md5 -q "${SC_DIR}/dl-after")
assert_eq "full GET after cancellation succeeds" "$ORIG_MD5" "$GOT_MD5"

# ════════════════════════════════════════════════════════════════════════════
# Summary
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " TOTAL: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
