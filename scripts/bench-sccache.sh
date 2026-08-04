#!/usr/bin/env bash
set -euo pipefail

# ── sccache-shaped multi-client throughput bench ───────────────────────────
#
# Models the primary production workload: many concurrent sccache clients
# against one spiceio → SMB share.
#
# sccache S3 access pattern (per compile unit, across N rustc processes):
#   • HEAD/GET on a content-addressed key under a shared prefix
#   • on miss: compile, then PUT the artifact
#   • on hit: GET the artifact
#   • object sizes: mostly small/medium (4 KiB–512 KiB); compound path ≤64 KiB
#   • keys: {prefix}/{hash} with a few stable parent dirs (dir-cache friendly)
#   • concurrency: tens–hundreds of in-flight ops from parallel cargo/rustc
#
# Usage:
#   SPICEIO_SMB_USER=u SPICEIO_SMB_PASS=p ./scripts/bench-sccache.sh
#   SPICEIO_BIN=./target/release/spiceio BENCH_CONCURRENCY=64 ./scripts/bench-sccache.sh
#
# Environment knobs:
#   BENCH_CONCURRENCY     parallel clients (default 64)
#   BENCH_OBJECTS         distinct keys in the working set (default 512)
#   BENCH_SMB_CONNECTIONS spiceio pool size (default 32 — multi-client fan-out)
#   SPICEIO_BIN           binary to run (default ./target/release/spiceio)

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-sccache-bench}"
BIND="${SPICEIO_BIND:-127.0.0.1:18390}"
CONCURRENCY="${BENCH_CONCURRENCY:-64}"
OBJECTS="${BENCH_OBJECTS:-512}"
SMB_CONNS="${BENCH_SMB_CONNECTIONS:-32}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="${SPICEIO_BIN:-./target/release/spiceio}"
ENDPOINT="http://${BIND}"
PREFIX="sccache-bench-$$"
TMP=$(mktemp -d /tmp/spiceio-sccache-bench.XXXXXX)

if [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[bench] building release binary..."
    cargo build --release --locked --quiet
fi

SPICEIO_PID=""
cleanup() {
    echo ""
    echo "[bench] cleaning up..."
    # Best-effort remote cleanup via curl (no aws dependency for teardown)
    for i in $(seq 0 $((OBJECTS - 1))); do
        curl -s -o /dev/null -X DELETE "${ENDPOINT}/${BUCKET}/${PREFIX}/$(printf '%03x' $((i % 4096)))/$(printf '%08x' "$i")" &
    done
    wait 2>/dev/null || true
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

echo "[bench] starting spiceio (pool=${SMB_CONNS}) -> smb://${SPICEIO_SMB_USER}@${SMB_SERVER}/${SMB_SHARE}"
SPICEIO_BIND="$BIND" \
SPICEIO_SMB_SERVER="$SMB_SERVER" \
SPICEIO_SMB_PORT="$SMB_PORT" \
SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
SPICEIO_SMB_SHARE="$SMB_SHARE" \
SPICEIO_BUCKET="$BUCKET" \
SPICEIO_REGION="$REGION" \
SPICEIO_SMB_CONNECTIONS="$SMB_CONNS" \
SPICEIO_LOG_FILE="${TMP}/spiceio.log" \
"$SPICEIO_BIN" >/dev/null 2>&1 &
SPICEIO_PID=$!

for i in $(seq 1 40); do
    curl -sf -o /dev/null "${ENDPOINT}/" 2>/dev/null && break
    if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
        echo "[bench] spiceio failed to start"; tail -20 "${TMP}/spiceio.log" 2>/dev/null; exit 1
    fi
    sleep 0.25
done
echo "[bench] ready  concurrency=${CONCURRENCY}  objects=${OBJECTS}  pool=${SMB_CONNS}"

# ── Artifact size mix (approximate sccache compressed-object distribution) ──
# 50% ≤64 KiB (compound Create+Write+Close), 30% mid (WAL), 20% larger WAL.
SIZES=(4096 16384 32768 49152 65536 98304 131072 262144 524288)
# weights roughly: more small than large
SIZE_PICK=(0 0 0 1 1 2 3 4 5 6 7 8)

now() { python3 -c 'import time;print(time.time())'; }
el()  { python3 -c "print(f'{$2-$1:.3f}')"; }
rate(){ python3 -c "print(f'{$1/($3-$2):.1f}')"; }
mbps(){ python3 -c "print(f'{$1/1048576/($3-$2):.1f}')"; }

key_for() {
    # Content-addressed layout: prefix/hhh/hhhhhhhh — few stable parents,
    # many leaf keys (matches sccache under a key prefix).
    local i=$1
    printf '%s/%03x/%08x' "$PREFIX" $((i % 4096)) "$i"
}

# Pre-generate payload files for each size class (zeros; size is what matters).
for sz in "${SIZES[@]}"; do
    dd if=/dev/zero of="${TMP}/p-${sz}" bs="$sz" count=1 2>/dev/null
done

put_one() {
    local i=$1
    local pick=${SIZE_PICK[$((i % ${#SIZE_PICK[@]}))]}
    local sz=${SIZES[$pick]}
    curl -sf --max-time 30 -X PUT --data-binary @"${TMP}/p-${sz}" \
        "${ENDPOINT}/${BUCKET}/$(key_for "$i")" \
        -H "Content-Length: ${sz}" -o /dev/null
}

get_one() {
    local i=$1
    curl -sf --max-time 30 \
        "${ENDPOINT}/${BUCKET}/$(key_for "$i")" -o /dev/null
}

head_one() {
    local i=$1
    # sccache existence probe — 200 or 404 both "succeed" for the bench
    local code
    code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
        -I "${ENDPOINT}/${BUCKET}/$(key_for "$i")")
    [[ "$code" == "200" || "$code" == "404" ]]
}

head_miss_one() {
    local i=$1
    local code
    code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' \
        -I "${ENDPOINT}/${BUCKET}/${PREFIX}/miss/$(printf '%08x' "$i")")
    [[ "$code" == "404" ]]
}

run_wave() {
    local n=$1
    shift
    local fn=$1
    local pids=()
    local errors=0
    local i=0
    while (( i < n )); do
        local batch=0
        pids=()
        while (( batch < CONCURRENCY && i < n )); do
            "$fn" "$i" &
            pids+=($!)
            i=$((i + 1))
            batch=$((batch + 1))
        done
        for pid in "${pids[@]}"; do
            wait "$pid" || errors=$((errors + 1))
        done
    done
    echo "$errors"
}

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " sccache-shaped multi-client bench"
echo " target: smb://${SMB_SERVER}/${SMB_SHARE}  bucket: ${BUCKET}"
echo "═══════════════════════════════════════════════════════════════"

# ── 1. Cold populate (many clients writing distinct artifacts) ────────────
echo ""
echo "── 1. Cold populate: ${OBJECTS} concurrent PUTs (mixed sizes) ──"
S=$(now)
ERR=$(run_wave "$OBJECTS" put_one)
E=$(now)
# Approximate total bytes from size mix (mean of SIZE_PICK distribution)
# SIZE_PICK mean ≈ index 3–4 → ~50–65 KiB; use 64 KiB * OBJECTS as estimate
BYTES_EST=$((OBJECTS * 65536))
printf "  %d PUTs in %ss  %s obj/s  ~%s MiB/s  errors=%s\n" \
    "$OBJECTS" "$(el "$S" "$E")" "$(rate "$OBJECTS" "$S" "$E")" \
    "$(mbps "$BYTES_EST" "$S" "$E")" "$ERR"

# ── 2. Warm hit storm (many clients reading existing cache) ───────────────
echo ""
echo "── 2. Warm GET hits: ${OBJECTS} concurrent GETs ──"
S=$(now)
ERR=$(run_wave "$OBJECTS" get_one)
E=$(now)
printf "  %d GETs in %ss  %s obj/s  ~%s MiB/s  errors=%s\n" \
    "$OBJECTS" "$(el "$S" "$E")" "$(rate "$OBJECTS" "$S" "$E")" \
    "$(mbps "$BYTES_EST" "$S" "$E")" "$ERR"

# ── 3. HEAD of existing keys (etag / existence after populate) ────────────
echo ""
echo "── 3. HEAD hits: ${OBJECTS} concurrent HEADs ──"
S=$(now)
ERR=$(run_wave "$OBJECTS" head_one)
E=$(now)
printf "  %d HEADs in %ss  %s req/s  errors=%s\n" \
    "$OBJECTS" "$(el "$S" "$E")" "$(rate "$OBJECTS" "$S" "$E")" "$ERR"

# ── 4. HEAD miss storm (cold compile units probing empty cache) ───────────
echo ""
echo "── 4. HEAD misses: ${OBJECTS} concurrent 404 probes ──"
S=$(now)
ERR=$(run_wave "$OBJECTS" head_miss_one)
E=$(now)
printf "  %d HEAD-miss in %ss  %s req/s  errors=%s\n" \
    "$OBJECTS" "$(el "$S" "$E")" "$(rate "$OBJECTS" "$S" "$E")" "$ERR"

# ── 5. Mixed multi-client cycle (closest to a live sccache fleet) ─────────
# 60% GET hit, 25% HEAD miss, 15% PUT new — weighted random-ish by index.
echo ""
echo "── 5. Mixed cycle: ${OBJECTS} ops (60% GET / 25% HEAD-miss / 15% PUT) ──"
mixed_one() {
    local i=$1
    local r=$((i % 20))
    if (( r < 12 )); then
        get_one $((i % OBJECTS))
    elif (( r < 17 )); then
        head_miss_one "$i"
    else
        # new keys beyond the working set
        local j=$((OBJECTS + i))
        local pick=${SIZE_PICK[$((j % ${#SIZE_PICK[@]}))]}
        local sz=${SIZES[$pick]}
        curl -sf --max-time 30 -X PUT --data-binary @"${TMP}/p-${sz}" \
            "${ENDPOINT}/${BUCKET}/$(key_for "$j")" \
            -H "Content-Length: ${sz}" -o /dev/null
    fi
}
S=$(now)
ERR=$(run_wave "$OBJECTS" mixed_one)
E=$(now)
printf "  %d mixed ops in %ss  %s ops/s  errors=%s\n" \
    "$OBJECTS" "$(el "$S" "$E")" "$(rate "$OBJECTS" "$S" "$E")" "$ERR"

# ── 6. Write-then-read pairs (store then immediate fetch) ─────────────────
echo ""
echo "── 6. PUT+GET pairs: ${CONCURRENCY} concurrent (sharing-path stress) ──"
pair_one() {
    local i=$1
    local j=$((OBJECTS * 2 + i))
    put_one "$j" && get_one "$j"
}
S=$(now)
ERR=$(run_wave "$CONCURRENCY" pair_one)
E=$(now)
printf "  %d pairs in %ss  %s pairs/s  errors=%s\n" \
    "$CONCURRENCY" "$(el "$S" "$E")" "$(rate "$CONCURRENCY" "$S" "$E")" "$ERR"

echo ""
echo "log notes: $(rg -c 'error|backed off|poison|capacity|reduced' "${TMP}/spiceio.log" 2>/dev/null || echo 0)"
rg -i 'backed off|capacity|reduced from|error:' "${TMP}/spiceio.log" 2>/dev/null | tail -8 || true
echo "═══════════════════════════════════════════════════════════════"
