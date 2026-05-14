#!/usr/bin/env bash
set -euo pipefail

# ── Live throughput benchmarks against a running spiceio instance ────────
#
# Usage: SPICEIO_SMB_USER=user SPICEIO_SMB_PASS=pass ./scripts/bench-live.sh
#
# Runs write and read throughput tests at various file sizes, plus
# concurrent multi-stream tests intended to saturate a 10G link.
#
# Environment knobs:
#   BENCH_CONCURRENCY    parallel streams in the concurrent tests (default 8)
#   BENCH_MOUNT_BASELINE 1 to also benchmark a raw mount_smbfs mount of the
#                          same share — gives a hard ceiling on what the link
#                          can do, so we can see spiceio's translation overhead
#
# Requires: aws cli, dd, curl, bc, perl (Time::HiRes).

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-bench}"
BIND="${SPICEIO_BIND:-127.0.0.1:18334}"
CONCURRENCY="${BENCH_CONCURRENCY:-8}"
MOUNT_BASELINE="${BENCH_MOUNT_BASELINE:-0}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/release/spiceio"
ENDPOINT="http://${BIND}"
AWS="aws --endpoint-url $ENDPOINT --no-sign-request"
PREFIX="bench-$$"

# ── Build release if needed ─────────────────────────────────────────────
if [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[bench] building release binary..."
    cargo build --release --locked --quiet
fi

# ── Cleanup ─────────────────────────────────────────────────────────────
SPICEIO_PID=""
MOUNT_POINT=""
cleanup() {
    echo ""
    echo "[bench] cleaning up..."
    $AWS s3 rm "s3://${BUCKET}/${PREFIX}/" --recursive --quiet 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    if [[ -n "$MOUNT_POINT" && -d "$MOUNT_POINT" ]]; then
        umount "$MOUNT_POINT" 2>/dev/null || true
        rmdir "$MOUNT_POINT" 2>/dev/null || true
    fi
    rm -f /tmp/spiceio-bench-*
}
trap cleanup EXIT

# ── Start spiceio ───────────────────────────────────────────────────────
echo "[bench] starting spiceio (release) -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}/${SMB_SHARE}"

SPICEIO_BIND="$BIND" \
SPICEIO_SMB_SERVER="$SMB_SERVER" \
SPICEIO_SMB_PORT="$SMB_PORT" \
SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
SPICEIO_SMB_SHARE="$SMB_SHARE" \
SPICEIO_BUCKET="$BUCKET" \
SPICEIO_REGION="$REGION" \
"$SPICEIO_BIN" 2>/dev/null &
SPICEIO_PID=$!

echo "[bench] waiting for spiceio..."
for i in $(seq 1 30); do
    if curl -sf -o /dev/null "${ENDPOINT}/" 2>/dev/null; then break; fi
    if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then echo "[bench] spiceio failed to start"; exit 1; fi
    sleep 0.5
done
echo "[bench] spiceio ready"

# ── Helpers ─────────────────────────────────────────────────────────────

# Generate a test file with /dev/zero (avoids CPU-bound /dev/urandom for large files)
gen_file() {
    local file=$1 size_bytes=$2
    dd if=/dev/zero of="$file" bs=1048576 count=$((size_bytes / 1048576)) 2>/dev/null
}

bench_write() {
    local size_bytes=$1 label=$2
    local file="/tmp/spiceio-bench-write-${label}"
    gen_file "$file" "$size_bytes"

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    $AWS s3 cp "$file" "s3://${BUCKET}/${PREFIX}/${label}" --quiet 2>/dev/null
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$size_bytes / $elapsed / 1048576" | bc -l)
    printf "  PUT %-8s  %6.2fs  %7.1f MiB/s\n" "$label" "$elapsed" "$mbps"
    rm -f "$file"
}

bench_read() {
    local size_bytes=$1 label=$2
    local file="/tmp/spiceio-bench-read-${label}"

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    $AWS s3 cp "s3://${BUCKET}/${PREFIX}/${label}" "$file" --quiet 2>/dev/null
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$size_bytes / $elapsed / 1048576" | bc -l)
    printf "  GET %-8s  %6.2fs  %7.1f MiB/s\n" "$label" "$elapsed" "$mbps"
    rm -f "$file"
}

bench_multi_write() {
    local count=$1 size_bytes=$2 label=$3
    local total=$((count * size_bytes))
    local file="/tmp/spiceio-bench-multi"
    gen_file "$file" "$size_bytes"

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    for i in $(seq 1 "$count"); do
        $AWS s3 cp "$file" "s3://${BUCKET}/${PREFIX}/multi-${label}-${i}" --quiet 2>/dev/null
    done
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$total / $elapsed / 1048576" | bc -l)
    printf "  PUT %dx%-5s  %6.2fs  %7.1f MiB/s  (%.0f files/s)\n" "$count" "$label" "$elapsed" "$mbps" "$(echo "$count / $elapsed" | bc -l)"
    rm -f "$file"
}

# Concurrent single-file PUT: N parallel uploads of `size_bytes`-each.
# Aggregate throughput is what hits the link — this is the test that
# meaningfully exercises a 10G NAS pipe.
bench_concurrent_write() {
    local concurrency=$1 size_bytes=$2 label=$3
    local total=$((concurrency * size_bytes))
    local file="/tmp/spiceio-bench-cwrite-${label}"
    gen_file "$file" "$size_bytes"

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    local pids=()
    for i in $(seq 1 "$concurrency"); do
        $AWS s3 cp "$file" "s3://${BUCKET}/${PREFIX}/cw-${label}-${i}" --quiet 2>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$total / $elapsed / 1048576" | bc -l)
    printf "  PUT x%-3d %-5s  %6.2fs  %7.1f MiB/s  (%.2f Gbit/s)\n" \
        "$concurrency" "$label" "$elapsed" "$mbps" \
        "$(echo "$mbps * 8 / 1024" | bc -l)"
    rm -f "$file"
}

bench_concurrent_read() {
    local concurrency=$1 size_bytes=$2 label=$3
    local total=$((concurrency * size_bytes))

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    local pids=()
    for i in $(seq 1 "$concurrency"); do
        $AWS s3 cp "s3://${BUCKET}/${PREFIX}/cw-${label}-${i}" "/tmp/spiceio-bench-cread-${label}-${i}" \
            --quiet 2>/dev/null &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait "$pid"
    done
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$total / $elapsed / 1048576" | bc -l)
    printf "  GET x%-3d %-5s  %6.2fs  %7.1f MiB/s  (%.2f Gbit/s)\n" \
        "$concurrency" "$label" "$elapsed" "$mbps" \
        "$(echo "$mbps * 8 / 1024" | bc -l)"
    rm -f /tmp/spiceio-bench-cread-${label}-*
}

# Optional raw-SMB baseline via mount_smbfs. Mounts the same share locally
# and runs the same dd-based write/read tests. Establishes the hard
# ceiling for what the link can do, so we can attribute spiceio's
# translation overhead.
bench_mount_baseline() {
    local user="$SPICEIO_SMB_USER"
    local pass="$SPICEIO_SMB_PASS"
    local server="$SMB_SERVER"
    local share="$SMB_SHARE"

    MOUNT_POINT="/tmp/spiceio-bench-mount-$$"
    mkdir -p "$MOUNT_POINT"
    local escaped_pass
    escaped_pass=$(printf '%s' "$pass" | perl -MURI::Escape -ne 'print uri_escape($_)')
    if ! mount_smbfs -N "//${user}:${escaped_pass}@${server}/${share}" "$MOUNT_POINT" 2>/dev/null; then
        echo "  (mount_smbfs failed — skipping baseline)"
        rmdir "$MOUNT_POINT" 2>/dev/null
        MOUNT_POINT=""
        return
    fi

    local target="${MOUNT_POINT}/${PREFIX}-mount-baseline"
    mkdir -p "$target"

    local label sizes labels
    sizes=(104857600 524288000)
    labels=("100M" "500M")
    for idx in "${!sizes[@]}"; do
        local size_bytes=${sizes[$idx]}
        label=${labels[$idx]}
        local file="/tmp/spiceio-bench-mountin-${label}"
        gen_file "$file" "$size_bytes"

        local start end elapsed mbps
        start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
        cp "$file" "${target}/${label}"
        end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
        elapsed=$(echo "$end - $start" | bc -l)
        mbps=$(echo "$size_bytes / $elapsed / 1048576" | bc -l)
        printf "  PUT mount  %-5s  %6.2fs  %7.1f MiB/s\n" "$label" "$elapsed" "$mbps"

        start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
        cp "${target}/${label}" "${file}.out"
        end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
        elapsed=$(echo "$end - $start" | bc -l)
        mbps=$(echo "$size_bytes / $elapsed / 1048576" | bc -l)
        printf "  GET mount  %-5s  %6.2fs  %7.1f MiB/s\n" "$label" "$elapsed" "$mbps"
        rm -f "$file" "${file}.out"
    done

    rm -rf "$target" 2>/dev/null
    umount "$MOUNT_POINT" 2>/dev/null
    rmdir "$MOUNT_POINT" 2>/dev/null
    MOUNT_POINT=""
}

# ── Run benchmarks ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " spiceio live throughput benchmarks"
echo " target: smb://${SMB_SERVER}/${SMB_SHARE}  bucket: ${BUCKET}"
echo "═══════════════════════════════════════════════════════════════"

# Single-file write: 1 + 10 + 50 + 100 + 500 + 1024 = 1685 MiB
echo ""
echo "── Single-file write throughput ──"
bench_write   1048576   "1M"
bench_write  10485760   "10M"
bench_write  52428800   "50M"
bench_write 104857600   "100M"
bench_write 524288000   "500M"
bench_write 1073741824  "1G"

# Single-file read: 1685 MiB (same files)
echo ""
echo "── Single-file read throughput ──"
bench_read   1048576   "1M"
bench_read  10485760   "10M"
bench_read  52428800   "50M"
bench_read 104857600   "100M"
bench_read 524288000   "500M"
bench_read 1073741824  "1G"

# Multi-file write: 100 + 200 + 500 = 800 MiB
echo ""
echo "── Multi-file write throughput ──"
bench_multi_write 100  1048576   "1M"
bench_multi_write  20 10485760   "10M"
bench_multi_write  10 52428800   "50M"

# Concurrent single-stream tests. Single-stream uploads top out at one TCP
# connection's worth of pipe; aggregate concurrent uploads is the test
# that actually saturates a 10G link.
echo ""
echo "── Concurrent write throughput (x${CONCURRENCY} parallel) ──"
bench_concurrent_write "$CONCURRENCY" 104857600  "100M"
bench_concurrent_write "$CONCURRENCY" 524288000  "500M"

echo ""
echo "── Concurrent read throughput (x${CONCURRENCY} parallel) ──"
bench_concurrent_read "$CONCURRENCY" 104857600  "100M"
bench_concurrent_read "$CONCURRENCY" 524288000  "500M"

if [[ "$MOUNT_BASELINE" == "1" ]]; then
    echo ""
    echo "── Raw mount_smbfs baseline (link ceiling) ──"
    bench_mount_baseline
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
