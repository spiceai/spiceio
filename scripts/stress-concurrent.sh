#!/usr/bin/env bash
set -euo pipefail

# ── Concurrent stress test ─────────────────────────────────────────────────
#
# Hammers spiceio with parallel S3 operations to stress the connection pool
# and verify no sharing violations under concurrent load.
#
# Usage: SPICEIO_SMB_USER=user SPICEIO_SMB_PASS=pass ./scripts/stress-concurrent.sh

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-stress}"
BIND="${SPICEIO_BIND:-127.0.0.1:18335}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/debug/spiceio"
ENDPOINT="http://${BIND}"
PREFIX="stress-$$"
TMPDIR_BASE=$(mktemp -d /tmp/spiceio-stress.XXXXXX)
PASS=0
FAIL=0
CONCURRENCY="${SPICEIO_STRESS_CONCURRENCY:-16}"
CURL_TIMEOUT="${SPICEIO_STRESS_TIMEOUT:-30}"

# ── Cleanup ────────────────────────────────────────────────────────────────

SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[stress] cleaning up..."
    aws --endpoint-url "$ENDPOINT" --no-sign-request \
        s3 rm "s3://${BUCKET}/${PREFIX}/" --recursive --quiet 2>/dev/null || true
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
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected='$expected', got='$actual')"
        FAIL=$((FAIL + 1))
    fi
}

s3_put() {
    curl -sf --max-time "$CURL_TIMEOUT" -X PUT --data-binary "@$1" \
        "${ENDPOINT}/${BUCKET}/$2" -o /dev/null
}

s3_get() {
    curl -sf --max-time "$CURL_TIMEOUT" \
        "${ENDPOINT}/${BUCKET}/$1" -o "$2"
}

# Wait for an explicit list of PIDs; sets WAIT_ERRORS to the failure count.
wait_pids() {
    WAIT_ERRORS=0
    for pid in "$@"; do
        wait "$pid" || WAIT_ERRORS=$((WAIT_ERRORS + 1))
    done
}

# ── Start spiceio ──────────────────────────────────────────────────────────

echo "[stress] starting spiceio -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}:${SMB_PORT}/${SMB_SHARE}"

BIND_PORT="${BIND##*:}"
STALE_PIDS=$(lsof -i ":${BIND_PORT}" -sTCP:LISTEN -t 2>/dev/null || true)
if [[ -n "$STALE_PIDS" ]]; then
    echo "[stress] port ${BIND_PORT} in use, killing..."
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

for i in $(seq 1 30); do
    if curl -sf --max-time 2 -o /dev/null "${ENDPOINT}/" 2>/dev/null; then break; fi
    if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
        echo "[stress] spiceio failed to start"; exit 1
    fi
    sleep 0.5
done
echo "[stress] spiceio ready (concurrency=${CONCURRENCY}, timeout=${CURL_TIMEOUT}s)"

# ════════════════════════════════════════════════════════════════════════════
# 1. Concurrent writes — N parallel PUTs to distinct keys
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 1. Concurrent writes (${CONCURRENCY} parallel PUTs, 4KB each)"
echo "═══════════════════════════════════════════════════════════════"

WRITE_DIR="${TMPDIR_BASE}/write"
mkdir -p "$WRITE_DIR"

for i in $(seq 1 "$CONCURRENCY"); do
    dd if=/dev/urandom of="${WRITE_DIR}/src-${i}" bs=4096 count=1 2>/dev/null
done

PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$CONCURRENCY"); do
    s3_put "${WRITE_DIR}/src-${i}" "${PREFIX}/w-${i}" &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
printf "  %d PUTs in %.2fs  (%.0f req/s)  errors=%d\n" "$CONCURRENCY" "$ELAPSED" "$(echo "$CONCURRENCY / $ELAPSED" | bc -l)" "$WAIT_ERRORS"

# Integrity: read each file back and compare MD5
PREV_PASS=$PASS
for i in $(seq 1 "$CONCURRENCY"); do
    s3_get "${PREFIX}/w-${i}" "${WRITE_DIR}/dl-${i}" 2>/dev/null || true
    ORIG=$(md5 -q "${WRITE_DIR}/src-${i}")
    GOT=$(md5 -q "${WRITE_DIR}/dl-${i}" 2>/dev/null || echo "MISSING")
    assert_eq "write-${i} integrity" "$ORIG" "$GOT"
done
echo "  integrity: $((PASS - PREV_PASS))/${CONCURRENCY} verified"

# ════════════════════════════════════════════════════════════════════════════
# 2. Concurrent reads — N parallel GETs of the same file
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 2. Concurrent reads (${CONCURRENCY} parallel GETs, same 64KB key)"
echo "═══════════════════════════════════════════════════════════════"

READ_DIR="${TMPDIR_BASE}/read"
mkdir -p "$READ_DIR"

dd if=/dev/urandom of="${READ_DIR}/shared-src" bs=1024 count=64 2>/dev/null
s3_put "${READ_DIR}/shared-src" "${PREFIX}/shared-64k"
EXPECT_MD5=$(md5 -q "${READ_DIR}/shared-src")

PREV_PASS=$PASS
PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$CONCURRENCY"); do
    s3_get "${PREFIX}/shared-64k" "${READ_DIR}/dl-${i}" &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
printf "  %d GETs in %.2fs  (%.0f req/s)  errors=%d\n" "$CONCURRENCY" "$ELAPSED" "$(echo "$CONCURRENCY / $ELAPSED" | bc -l)" "$WAIT_ERRORS"

for i in $(seq 1 "$CONCURRENCY"); do
    GOT=$(md5 -q "${READ_DIR}/dl-${i}" 2>/dev/null || echo "MISSING")
    assert_eq "read-${i} integrity" "$EXPECT_MD5" "$GOT"
done
echo "  integrity: $((PASS - PREV_PASS))/${CONCURRENCY} verified"

# ════════════════════════════════════════════════════════════════════════════
# 3. Write-then-read (sharing violation stress) — the sccache pattern
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 3. Write-then-read (${CONCURRENCY} parallel, distinct keys)"
echo "═══════════════════════════════════════════════════════════════"

WR_DIR="${TMPDIR_BASE}/wr"
mkdir -p "$WR_DIR"

for i in $(seq 1 "$CONCURRENCY"); do
    dd if=/dev/urandom of="${WR_DIR}/src-${i}" bs=4096 count=1 2>/dev/null
done

# Each job: PUT then immediately GET the same key — reproduces sharing violation
do_write_read() {
    local i=$1
    s3_put "${WR_DIR}/src-${i}" "${PREFIX}/wr-${i}" || return 1
    s3_get "${PREFIX}/wr-${i}" "${WR_DIR}/dl-${i}" || return 1
}

PREV_PASS=$PASS
PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$CONCURRENCY"); do
    do_write_read "$i" &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
printf "  %d PUT+GETs in %.2fs  (%.0f pairs/s)  errors=%d\n" "$CONCURRENCY" "$ELAPSED" "$(echo "$CONCURRENCY / $ELAPSED" | bc -l)" "$WAIT_ERRORS"

for i in $(seq 1 "$CONCURRENCY"); do
    ORIG=$(md5 -q "${WR_DIR}/src-${i}")
    GOT=$(md5 -q "${WR_DIR}/dl-${i}" 2>/dev/null || echo "MISSING")
    assert_eq "wr-${i} integrity" "$ORIG" "$GOT"
done
echo "  integrity: $((PASS - PREV_PASS))/${CONCURRENCY} verified"

# ════════════════════════════════════════════════════════════════════════════
# 4. Mixed concurrent ops — reads and writes to the SAME key
#    Concurrent writes to the same SMB file cause STATUS_SHARING_VIOLATION
#    (expected). We verify: no data corruption, and the final state is valid.
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 4. Mixed read/write contention (${CONCURRENCY} ops, same key)"
echo "═══════════════════════════════════════════════════════════════"

MIX_DIR="${TMPDIR_BASE}/mix"
mkdir -p "$MIX_DIR"

# Seed the key so readers have something to get
dd if=/dev/urandom of="${MIX_DIR}/seed" bs=4096 count=1 2>/dev/null
s3_put "${MIX_DIR}/seed" "${PREFIX}/contended"
SEED_MD5=$(md5 -q "${MIX_DIR}/seed")

# Pre-generate writer files
for i in $(seq 1 "$CONCURRENCY"); do
    if (( i % 3 == 0 )); then
        dd if=/dev/urandom of="${MIX_DIR}/w-${i}" bs=4096 count=1 2>/dev/null
    fi
done

PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$CONCURRENCY"); do
    if (( i % 3 == 0 )); then
        # 1/3 writers — some will hit sharing violations (expected)
        s3_put "${MIX_DIR}/w-${i}" "${PREFIX}/contended" &
        PIDS+=($!)
    else
        # 2/3 readers
        s3_get "${PREFIX}/contended" "${MIX_DIR}/r-${i}" &
        PIDS+=($!)
    fi
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
printf "  %d mixed ops in %.2fs  (%.0f ops/s)  sharing_violations=%d (expected)\n" \
    "$CONCURRENCY" "$ELAPSED" "$(echo "$CONCURRENCY / $ELAPSED" | bc -l)" "$WAIT_ERRORS"

# Build set of valid MD5s (seed + all writer versions)
VALID_MD5S=("$SEED_MD5")
for i in $(seq 1 "$CONCURRENCY"); do
    if (( i % 3 == 0 )) && [[ -f "${MIX_DIR}/w-${i}" ]]; then
        VALID_MD5S+=("$(md5 -q "${MIX_DIR}/w-${i}")")
    fi
done

# Verify no data corruption. Possible outcomes for each read:
#   - Missing file: sharing violation prevented the read (acceptable)
#   - Empty/short file: caught between truncate and write (acceptable)
#   - Full-size file matching a known version: correct
#   - Full-size file NOT matching any known version: DATA CORRUPTION
PREV_PASS=$PASS
READ_OK=0
READ_TOTAL=0
READ_RACING=0
for i in $(seq 1 "$CONCURRENCY"); do
    if (( i % 3 != 0 )); then
        READ_TOTAL=$((READ_TOTAL + 1))
        if [[ ! -f "${MIX_DIR}/r-${i}" ]]; then
            # Sharing violation or HTTP error — acceptable
            READ_RACING=$((READ_RACING + 1))
            READ_OK=$((READ_OK + 1))
            PASS=$((PASS + 1))
            continue
        fi
        GOT_SIZE=$(wc -c < "${MIX_DIR}/r-${i}")
        if (( GOT_SIZE != 4096 )); then
            # Partial read during overwrite — acceptable
            READ_RACING=$((READ_RACING + 1))
            READ_OK=$((READ_OK + 1))
            PASS=$((PASS + 1))
            continue
        fi
        GOT_MD5=$(md5 -q "${MIX_DIR}/r-${i}")
        MATCHED=false
        for valid in "${VALID_MD5S[@]}"; do
            if [[ "$GOT_MD5" == "$valid" ]]; then
                MATCHED=true
                break
            fi
        done
        if $MATCHED; then
            READ_OK=$((READ_OK + 1))
            PASS=$((PASS + 1))
        else
            echo "  FAIL: contended read-${i} is 4096B but matches NO known version (data corruption)"
            FAIL=$((FAIL + 1))
        fi
    fi
done

# Final value must match a known version
FINAL_FILE="${MIX_DIR}/final"
s3_get "${PREFIX}/contended" "$FINAL_FILE" 2>/dev/null || true
if [[ -f "$FINAL_FILE" ]]; then
    FINAL_MD5=$(md5 -q "$FINAL_FILE")
    FOUND_MATCH=false
    for valid in "${VALID_MD5S[@]}"; do
        if [[ "$FINAL_MD5" == "$valid" ]]; then
            FOUND_MATCH=true
            break
        fi
    done
    if $FOUND_MATCH; then
        PASS=$((PASS + 1))
    else
        echo "  FAIL: final value doesn't match any known version (corruption?)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "  FAIL: could not read final value"
    FAIL=$((FAIL + 1))
fi
echo "  integrity: $((PASS - PREV_PASS)) checks passed, reads=${READ_OK}/${READ_TOTAL} (${READ_RACING} raced)"

# ════════════════════════════════════════════════════════════════════════════
# 5. Concurrent large-file streaming (1MB — exercises pipelined reads)
# ════════════════════════════════════════════════════════════════════════════

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 5. Concurrent large-file I/O (8 x 1MB — pipelined reads)"
echo "═══════════════════════════════════════════════════════════════"

LARGE_DIR="${TMPDIR_BASE}/large"
mkdir -p "$LARGE_DIR"
LARGE_N=8

for i in $(seq 1 "$LARGE_N"); do
    dd if=/dev/urandom of="${LARGE_DIR}/src-${i}" bs=1024 count=1024 2>/dev/null
done

# Parallel PUT
PREV_PASS=$PASS
PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$LARGE_N"); do
    s3_put "${LARGE_DIR}/src-${i}" "${PREFIX}/large-${i}" &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
MBPS=$(echo "$LARGE_N * 1048576 / $ELAPSED / 1048576" | bc -l)
printf "  %d x 1MB PUTs in %.2fs  (%.1f MiB/s)  errors=%d\n" "$LARGE_N" "$ELAPSED" "$MBPS" "$WAIT_ERRORS"

# Parallel GET
PIDS=()
START=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
for i in $(seq 1 "$LARGE_N"); do
    s3_get "${PREFIX}/large-${i}" "${LARGE_DIR}/dl-${i}" &
    PIDS+=($!)
done
wait_pids "${PIDS[@]}"
END=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
ELAPSED=$(echo "$END - $START" | bc -l)
MBPS=$(echo "$LARGE_N * 1048576 / $ELAPSED / 1048576" | bc -l)
printf "  %d x 1MB GETs in %.2fs  (%.1f MiB/s)  errors=%d\n" "$LARGE_N" "$ELAPSED" "$MBPS" "$WAIT_ERRORS"

# Integrity: every file must match
for i in $(seq 1 "$LARGE_N"); do
    ORIG=$(md5 -q "${LARGE_DIR}/src-${i}")
    GOT=$(md5 -q "${LARGE_DIR}/dl-${i}" 2>/dev/null || echo "MISSING")
    assert_eq "large-${i} integrity" "$ORIG" "$GOT"
done
echo "  integrity: $((PASS - PREV_PASS))/${LARGE_N} verified"

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
