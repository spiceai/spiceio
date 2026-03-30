#!/usr/bin/env bash
set -euo pipefail

# ── Live throughput benchmarks against a running spiceio instance ────────
#
# Usage: SPICEIO_SMB_USER=user SPICEIO_SMB_PASS=pass ./scripts/bench-live.sh
#
# Runs write and read throughput tests at various file sizes up to 10GB total
# data volume. Requires: aws cli, dd, md5 (macOS).

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-bench}"
BIND="${SPICEIO_BIND:-127.0.0.1:18334}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/release/spiceio"
ENDPOINT="http://${BIND}"
AWS="aws --endpoint-url $ENDPOINT --no-sign-request"
PREFIX="bench-$$"

# ── Build release if needed ─────────────────────────────────────────────
if [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[bench] building release binary..."
    cargo build --release --quiet
fi

# ── Cleanup ─────────────────────────────────────────────────────────────
SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[bench] cleaning up..."
    $AWS s3 rm "s3://${BUCKET}/${PREFIX}/" --recursive --quiet 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
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
human_size() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        printf "%.1fG" "$(echo "$bytes / 1073741824" | bc -l)"
    elif (( bytes >= 1048576 )); then
        printf "%.1fM" "$(echo "$bytes / 1048576" | bc -l)"
    elif (( bytes >= 1024 )); then
        printf "%.0fK" "$(echo "$bytes / 1024" | bc -l)"
    else
        printf "%dB" "$bytes"
    fi
}

bench_write() {
    local size_bytes=$1 label=$2
    local file="/tmp/spiceio-bench-write-${label}"
    dd if=/dev/urandom of="$file" bs=1048576 count=$((size_bytes / 1048576)) 2>/dev/null

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    $AWS s3 cp "$file" "s3://${BUCKET}/${PREFIX}/${label}" --quiet 2>/dev/null
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$size_bytes / $elapsed / 1048576" | bc -l)
    printf "  PUT %-8s  %6.2fs  %7.1f MB/s\n" "$label" "$elapsed" "$mbps"
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
    printf "  GET %-8s  %6.2fs  %7.1f MB/s\n" "$label" "$elapsed" "$mbps"
    rm -f "$file"
}

bench_multi_write() {
    local count=$1 size_bytes=$2 label=$3
    local total=$((count * size_bytes))
    local file="/tmp/spiceio-bench-multi"
    dd if=/dev/urandom of="$file" bs=1048576 count=$((size_bytes / 1048576)) 2>/dev/null

    local start end elapsed mbps
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    for i in $(seq 1 "$count"); do
        $AWS s3 cp "$file" "s3://${BUCKET}/${PREFIX}/multi-${label}-${i}" --quiet 2>/dev/null
    done
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    mbps=$(echo "$total / $elapsed / 1048576" | bc -l)
    printf "  PUT %dx%-5s  %6.2fs  %7.1f MB/s  (%.0f files/s)\n" "$count" "$label" "$elapsed" "$mbps" "$(echo "$count / $elapsed" | bc -l)"
    rm -f "$file"
}

# ── Run benchmarks ──────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " spiceio live throughput benchmarks"
echo " target: smb://${SMB_SERVER}/${SMB_SHARE}  bucket: ${BUCKET}"
echo "═══════════════════════════════════════════════════════════════"

echo ""
echo "── Single-file write throughput ──"
bench_write   1048576   "1M"
bench_write  10485760   "10M"
bench_write  52428800   "50M"
bench_write 104857600   "100M"
bench_write 524288000   "500M"
bench_write 1073741824  "1G"

echo ""
echo "── Single-file read throughput ──"
bench_read   1048576   "1M"
bench_read  10485760   "10M"
bench_read  52428800   "50M"
bench_read 104857600   "100M"
bench_read 524288000   "500M"
bench_read 1073741824  "1G"

echo ""
echo "── Multi-file write throughput ──"
bench_multi_write 100  1048576   "1M"
bench_multi_write  20 10485760   "10M"
bench_multi_write  10 52428800   "50M"

echo ""
echo "── Aggregate: ~10GB total written + read ──"
TOTAL_WRITTEN=$((1+10+50+100+500+1024 + 100+200+500))  # MB
TOTAL_READ=$((1+10+50+100+500+1024))                     # MB
echo "  Total written: ~${TOTAL_WRITTEN}M"
echo "  Total read:    ~${TOTAL_READ}M"
echo ""
echo "═══════════════════════════════════════════════════════════════"
