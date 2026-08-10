#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# sccache-shaped synthetic throughput bench
#
# Answers "where does an sccache client's time go through spiceio?" by driving
# the proxy with the request shape sccache produces — persistent keep-alive
# connections, content-addressed keys, a realistic object-size mix — and
# recording latency on both sides of the proxy at once:
#
#   client side  spiceio-loadgen: ops/s, MiB/s, mean/p50/p90/p99/p99.9, TTFB
#   server side  SPICEIO_ACCESS_LOG: how long spiceio held each request
#
# The gap between them is HTTP framing and client cost; the server side alone is
# spiceio plus its SMB round trips. Splitting them is the point — one end-to-end
# number cannot tell you which half to fix.
#
# It sweeps concurrency because the interesting limit is not single-request
# latency, it is the point where more concurrency stops buying throughput.
#
# Usage:
#   SPICEIO_SMB_USER=u SPICEIO_SMB_PASS=p ./scripts/bench-sccache.sh
#   BENCH_CONCURRENCY="8 32 128" BENCH_OBJECTS=1024 ./scripts/bench-sccache.sh
#
# Knobs:
#   BENCH_CONCURRENCY      space-separated sweep (default "1 8 32 64 128 256")
#   BENCH_OBJECTS          distinct keys per phase (default 512)
#   BENCH_OPS_PER_WORKER   requests each worker issues per phase (default 24)
#   BENCH_SMB_CONNECTIONS  spiceio pool size (default: spiceio's own)
#   BENCH_PHASES           loadgen phases (default put,get,head-hit,head-miss,mixed)
#   BENCH_PASSES           which passes to run (default "cached nocache")
#                          `cached`/`nocache` pin SPICEIO_WRITE_BACK=0 so they
#                          are baselines; also available: `writeback` (the
#                          shipped default) and `nospill` (SPICEIO_SPILL_DIR=off),
#                          for isolating the write-ack and disk-tier changes
#   BENCH_OUT              results directory (default benches/results)
#   BENCH_LABEL            label recorded in the report (default: git describe)
#   BENCH_KEEP             1 to leave written objects on the share (default 0)
# ═══════════════════════════════════════════════════════════════════════════

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-sccache-bench}"
BIND="${SPICEIO_BIND:-127.0.0.1:18390}"

CONCURRENCY_SWEEP="${BENCH_CONCURRENCY:-1 8 32 64 128 256}"
OBJECTS="${BENCH_OBJECTS:-512}"
# Pool size: unset by default, so the bench measures the pool spiceio actually
# ships with (`default_pool_size`, 2x CPU clamped 8-32) rather than a number
# pinned here. A hard-coded default silently drifts from the product — this was
# 12 while the binary defaulted to 16, so every recorded run under-provisioned
# the thing under test. Set BENCH_SMB_CONNECTIONS to sweep it deliberately.
SMB_CONNS="${BENCH_SMB_CONNECTIONS:-}"
PHASES="${BENCH_PHASES:-put,get,head-hit,head-miss,mixed}"
# Which passes to run. `cached` is the shipping configuration; `nocache`
# disables the GET body cache so every read reaches the NAS. Narrowing this is
# how a follow-up experiment (pool size, max I/O) isolates one variable.
SELECTED_PASSES="${BENCH_PASSES:-cached nocache}"
OPS_PER_WORKER="${BENCH_OPS_PER_WORKER:-24}"
KEEP="${BENCH_KEEP:-0}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="${BENCH_OUT:-benches/results}"
SPICEIO_BIN="${SPICEIO_BIN:-./target/release/spiceio}"
LOADGEN_BIN="${LOADGEN_BIN:-./target/release/spiceio-loadgen}"
ENDPOINT="http://${BIND}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LABEL="${BENCH_LABEL:-$(git describe --always --dirty 2>/dev/null || echo unknown)}"
PREFIX="bench/${RUN_ID}"
RESULTS="${OUT_DIR}/${RUN_ID}"
TMP="$(mktemp -d /tmp/spiceio-bench.XXXXXX)"
PASSES=()

mkdir -p "$RESULTS"

# Ambient sccache would route this build through a cache living on the very
# share we are about to measure.
unset RUSTC_WRAPPER SCCACHE_DIR

# Always rebuild the default paths — cargo is a no-op when they are current, and
# silently benchmarking a stale binary (or one predating a new loadgen flag) is
# a far more expensive mistake than a redundant build.
if [[ "$SPICEIO_BIN" == "./target/release/spiceio" ]]; then
    echo "[bench] building release binary..."
    cargo build --release --locked --quiet
elif [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[bench] SPICEIO_BIN ${SPICEIO_BIN} is not executable" >&2
    exit 1
fi
if [[ "$LOADGEN_BIN" == "./target/release/spiceio-loadgen" ]]; then
    echo "[bench] building load generator..."
    cargo build --release --locked --quiet --features loadgen --bin spiceio-loadgen
elif [[ ! -x "$LOADGEN_BIN" ]]; then
    echo "[bench] LOADGEN_BIN ${LOADGEN_BIN} is not executable" >&2
    exit 1
fi

# ── spiceio lifecycle ─────────────────────────────────────────────────────

SPICEIO_PID=""
ACCESS_FILE=""

stop_spiceio() {
    [[ -n "$SPICEIO_PID" ]] || return 0
    # SIGTERM, not SIGKILL: graceful shutdown flushes the access-log buffer, and
    # a killed process takes the tail of the run's records with it.
    kill -TERM "$SPICEIO_PID" 2>/dev/null || true
    for _ in $(seq 1 60); do
        kill -0 "$SPICEIO_PID" 2>/dev/null || break
        sleep 0.25
    done
    kill -9 "$SPICEIO_PID" 2>/dev/null || true
    wait "$SPICEIO_PID" 2>/dev/null || true
    SPICEIO_PID=""
}

# start_spiceio <tag> [extra env assignments...]
start_spiceio() {
    local tag="$1"
    shift
    # Proxy log goes with the results: when a pass shows 5xx or failed writes,
    # this is where the reason is recorded, and the EXIT trap removes TMP.
    local log="${RESULTS}/spiceio-${tag}.log"
    ACCESS_FILE="${TMP}/access-${tag}.tsv"

    # Reclaim the port from an aborted previous run rather than silently
    # benchmarking whatever is already listening on it.
    local port="${BIND##*:}" stale
    stale="$(lsof -i ":${port}" -sTCP:LISTEN -t 2>/dev/null || true)"
    if [[ -n "$stale" ]]; then
        echo "[bench] port ${port} busy (pid ${stale}); reclaiming"
        kill $stale 2>/dev/null || true
        sleep 1
    fi

    env "$@" \
        SPICEIO_BIND="$BIND" \
        SPICEIO_SMB_SERVER="$SMB_SERVER" \
        SPICEIO_SMB_PORT="$SMB_PORT" \
        SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
        SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
        SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
        SPICEIO_SMB_SHARE="$SMB_SHARE" \
        SPICEIO_BUCKET="$BUCKET" \
        SPICEIO_REGION="$REGION" \
        ${SMB_CONNS:+SPICEIO_SMB_CONNECTIONS=$SMB_CONNS} \
        SPICEIO_LOG_FILE="$log" \
        SPICEIO_ACCESS_LOG="$ACCESS_FILE" \
        "$SPICEIO_BIN" >/dev/null 2>&1 &
    SPICEIO_PID=$!

    # Wait for SMB readiness, not merely a bound socket: requests served before
    # the share connects get 503s that would be scored as proxy latency.
    local i
    for i in $(seq 1 120); do
        if grep -q 'ready, listening on' "$log" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
            echo "[bench] spiceio failed to start:" >&2
            tail -20 "$log" >&2 2>/dev/null || true
            SPICEIO_PID=""
            return 1
        fi
        sleep 0.5
    done
    echo "[bench] spiceio did not become ready within 60s" >&2
    return 1
}

# Delete everything this run wrote. Runs while a proxy is up.
delete_objects() {
    local pass
    for pass in ${PASSES[@]+"${PASSES[@]}"}; do
        "$LOADGEN_BIN" --endpoint "$ENDPOINT" --bucket "$BUCKET" \
            --prefix "${PREFIX}/${pass}" --concurrency 32 --objects "$OBJECTS" \
            --ops "$OBJECTS" --phase delete >/dev/null 2>&1 || true
    done
}

cleanup() {
    if [[ "$KEEP" != "1" && ${#PASSES[@]} -gt 0 ]]; then
        if [[ -z "$SPICEIO_PID" ]]; then
            # Aborted before the normal teardown — stand an instance back up so
            # a few hundred MiB of benchmark objects do not sit on a shared NAS.
            start_spiceio cleanup >/dev/null 2>&1 || true
        fi
        if [[ -n "$SPICEIO_PID" ]]; then
            echo "[bench] removing benchmark objects from the share..."
            delete_objects
        fi
    fi
    stop_spiceio
    rm -rf "$TMP"
}
trap cleanup EXIT

# ── Server-side attribution from the access log ───────────────────────────
#
# Per method: request count, bytes moved, and percentiles of the time spiceio
# held the request. `total_us` covers the whole response including streaming the
# body; `head_us` stops at the response head (for GetObject: the SMB open plus
# first read), so the gap between them is streaming cost.
summarize_access() {
    local file="$1" since_ms="$2" out="$3"
    : >"$out"
    [[ -s "$file" ]] || return 0
    # Python rather than awk: a sweep point at high concurrency produces tens of
    # thousands of records, and exact percentiles need them sorted. awk has no
    # built-in sort, and a hand-rolled one is O(n²) — slow enough at this scale
    # to show up as bench wall-clock rather than as measured latency.
    python3 - "$file" "$since_ms" >"$out" <<'PY'
import sys

path, since = sys.argv[1], int(sys.argv[2])
by = {}
with open(path, errors="replace") as fh:
    for line in fh:
        if line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if len(f) < 8:
            continue
        try:
            t_ms, status = int(f[0]), int(f[2])
            req, resp = int(f[3]), int(f[4])
            head_us, total_us = int(f[5]), int(f[6])
        except ValueError:
            continue
        if t_ms < since:
            continue
        e = by.setdefault(f[1], {"tot": [], "head": [], "bytes": 0, "err": 0})
        e["tot"].append(total_us)
        e["head"].append(head_us)
        e["bytes"] += req + resp
        if status >= 500:
            e["err"] += 1

def pct(sorted_vals, p):
    if not sorted_vals:
        return 0
    # Nearest rank, matching the load generator's client-side percentiles so the
    # two sides of the same request are directly comparable.
    import math
    r = max(1, min(len(sorted_vals), math.ceil(p * len(sorted_vals))))
    return sorted_vals[r - 1]

for method in sorted(by):
    e = by[method]
    t, h = sorted(e["tot"]), sorted(e["head"])
    print("\t".join(str(v) for v in (
        method, len(t), e["bytes"],
        pct(t, 0.50), pct(t, 0.90), pct(t, 0.99), t[-1] if t else 0,
        pct(h, 0.50), pct(h, 0.99), e["err"],
    )))
PY
}

print_access_table() {
    local out="$1" indent="${2:-  }"
    if [[ ! -s "$out" ]]; then
        echo "${indent}(no access-log records in window)"
        return 0
    fi
    printf "%s%-7s %8s %9s %10s %10s %10s %10s %10s %10s %5s\n" \
        "$indent" method count MiB p50 p90 p99 max head_p50 head_p99 5xx
    local m cnt bytes p50 p90 p99 mx hp50 hp99 errs
    while IFS=$'\t' read -r m cnt bytes p50 p90 p99 mx hp50 hp99 errs; do
        awk -v i="$indent" -v m="$m" -v c="$cnt" -v b="$bytes" -v a="$p50" -v d="$p90" \
            -v e="$p99" -v f="$mx" -v g="$hp50" -v j="$hp99" -v k="$errs" \
            'BEGIN{printf "%s%-7s %8d %9.1f %8.2fms %8.2fms %8.2fms %8.2fms %8.2fms %8.2fms %5d\n",
                   i, m, c, b/1048576, a/1000, d/1000, e/1000, f/1000, g/1000, j/1000, k}'
    done <"$out"
}

now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# ── One pass: the whole concurrency sweep against a running spiceio ───────

run_pass() {
    local pass="$1"
    PASSES+=("$pass")
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo " pass: ${pass}"
    echo "═══════════════════════════════════════════════════════════════════"

    local conc t0 json acc ops
    for conc in $CONCURRENCY_SWEEP; do
        t0="$(now_ms)"
        json="${RESULTS}/${pass}-c${conc}.json"
        acc="${RESULTS}/${pass}-c${conc}-server.tsv"
        # Work per phase scales with concurrency: at a fixed op count the
        # high-concurrency points would be almost entirely ramp-up, and the
        # sweep would report a knee that is an artefact of the harness.
        ops=$(( conc * OPS_PER_WORKER ))
        if (( ops < OBJECTS )); then ops=$OBJECTS; fi
        echo ""
        echo "── ${pass} @ concurrency ${conc} (${ops} ops/phase) ─────────────"
        "$LOADGEN_BIN" \
            --endpoint "$ENDPOINT" \
            --bucket "$BUCKET" \
            --prefix "${PREFIX}/${pass}" \
            --concurrency "$conc" \
            --objects "$OBJECTS" \
            --ops "$ops" \
            --phase "$PHASES" \
            --warmup 2 \
            --label "${LABEL} ${pass} c${conc}" \
            --json "$json" || true

        summarize_access "$ACCESS_FILE" "$t0" "$acc"
        echo ""
        echo "  server-side (time spiceio held the request):"
        print_access_table "$acc"
    done
}

# ── Go ────────────────────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " spiceio sccache bench — ${LABEL}"
echo " target : smb://${SMB_SERVER}/${SMB_SHARE}  bucket=${BUCKET}"
echo " pool   : ${SMB_CONNS:-spiceio default} SMB connections"
echo " sweep  : concurrency [${CONCURRENCY_SWEEP}]  objects=${OBJECTS}  ops/worker=${OPS_PER_WORKER}"
echo " phases : ${PHASES}"
echo " results: ${RESULTS}"
echo "═══════════════════════════════════════════════════════════════════"

# Each pass gets its own spiceio so the configuration under test is the one it
# started with, and a fresh proxy cache. Objects are deleted between passes so a
# pass's `put` phase measures first writes, not overwrites of the last pass.
for pass in $SELECTED_PASSES; do
    if [[ ${#PASSES[@]} -gt 0 ]]; then
        delete_objects
        stop_spiceio
    fi
    case "$pass" in
        cached)
            # Write-back pinned off: it is on by default, and a baseline that
            # inherited it would make the `writeback` pass a comparison against
            # itself. Same reason the `nocache` pass pins the cache off.
            start_spiceio cached SPICEIO_WRITE_BACK=0
            ;;
        nocache)
            start_spiceio nocache SPICEIO_WRITE_BACK=0 \
                SPICEIO_OBJECT_CACHE_BYTES=0 SPICEIO_OBJECT_CACHE_ENTRIES=0
            ;;
        writeback)
            # PUT acknowledged from memory; the NAS write happens behind it (the
            # shipped default). The number to read is the `put` phase against the
            # `cached` pass, which pins it off.
            start_spiceio writeback SPICEIO_WRITE_BACK=1
            ;;
        nospill)
            # Memory tier only, for attributing a change to the disk tier rather
            # than to the cache as a whole.
            start_spiceio nospill SPICEIO_SPILL_DIR=off
            ;;
        *)
            echo "[bench] unknown pass ${pass}; expected one of: cached nocache writeback nospill" >&2
            exit 1
            ;;
    esac
    run_pass "$pass"
    cp "$ACCESS_FILE" "${RESULTS}/access-${pass}.tsv" 2>/dev/null || true
done

# ── Report ────────────────────────────────────────────────────────────────

REPORT="${RESULTS}/report.md"
{
    echo "# spiceio sccache bench — ${RUN_ID}"
    echo
    echo "| field | value |"
    echo "| --- | --- |"
    echo "| label | \`${LABEL}\` |"
    echo "| target | \`smb://${SMB_SERVER}/${SMB_SHARE}\` |"
    echo "| SMB pool | ${SMB_CONNS:-spiceio default} |"
    echo "| key space | ${OBJECTS} objects |"
    echo "| ops per worker per phase | ${OPS_PER_WORKER} |"
    echo "| phases | \`${PHASES}\` |"
    echo "| host | \`$(uname -sr) $(sysctl -n hw.model 2>/dev/null || echo '?')\` |"
    echo
    echo "Client-observed latency from \`spiceio-loadgen\` over persistent"
    echo "keep-alive connections. \`cached\` is the shipping configuration;"
    echo "\`nocache\` disables the GET body cache so every read reaches the NAS."
    echo
    for pass in ${PASSES[@]+"${PASSES[@]}"}; do
        echo "## ${pass}"
        echo
        echo "| conc | phase | ops/s | MiB/s | p50 | p90 | p99 | p99.9 | err |"
        echo "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
        for conc in $CONCURRENCY_SWEEP; do
            f="${RESULTS}/${pass}-c${conc}.json"
            [[ -s "$f" ]] || continue
            python3 - "$f" "$conc" <<'PY'
import json, sys
path, conc = sys.argv[1], sys.argv[2]
with open(path) as fh:
    doc = json.load(fh)
ms = lambda v: f"{v/1000:.2f}ms"
for p in doc["phases"]:
    lat = p["latency_us"]
    # `errors` now includes wrong-status responses, not just transport
    # failures — the load generator classifies each reply against what its
    # operation expects. Naming them keeps a run that "succeeded" at 400
    # MiB/s while answering every PUT with 404 from reading as a good result.
    err = sum(p["errors"].values()) if p["errors"] else 0
    detail = ", ".join(f"{k}: {v}" for k, v in sorted(p["errors"].items()))
    err_cell = f"{err}" + (f" ({detail})" if detail else "")
    print(f"| {conc} | {p['phase']} | {p['ops_per_sec']:.1f} | {p['mib_per_sec']:.1f} "
          f"| {ms(lat['p50'])} | {ms(lat['p90'])} | {ms(lat['p99'])} "
          f"| {ms(lat['p999'])} | {err_cell} |")
PY
        done
        echo
        echo "### ${pass} — server-side (time spiceio held the request)"
        echo
        echo '```'
        for conc in $CONCURRENCY_SWEEP; do
            acc="${RESULTS}/${pass}-c${conc}-server.tsv"
            [[ -s "$acc" ]] || continue
            echo "concurrency ${conc}:"
            print_access_table "$acc" "  "
            echo
        done
        echo '```'
        echo
    done
    echo "## Raw"
    echo
    echo "- Per-run JSON: \`${RESULTS}/<pass>-c<conc>.json\`"
    echo "- Per-run server summary: \`${RESULTS}/<pass>-c<conc>-server.tsv\`"
    echo "- Full access log (TSV \`t_ms method status req_bytes resp_bytes head_us total_us path\`):"
    echo "  \`${RESULTS}/access-<pass>.tsv\`"
} >"$REPORT"

# Surface failures in the run summary. A benchmark whose headline is throughput
# will otherwise happily report a great number for a proxy that stored nothing.
TOTAL_FAILED=0
for f in "${RESULTS}"/*.json; do
    [[ -s "$f" ]] || continue
    n=$(python3 -c '
import json, sys
with open(sys.argv[1]) as fh:
    doc = json.load(fh)
print(sum(sum(p["errors"].values()) for p in doc["phases"] if p["errors"]))
' "$f" 2>/dev/null || echo 0)
    TOTAL_FAILED=$(( TOTAL_FAILED + n ))
done

echo ""
echo "═══════════════════════════════════════════════════════════════════"
if [[ "$TOTAL_FAILED" -gt 0 ]]; then
    echo " ⚠ ${TOTAL_FAILED} failed request(s) across the sweep — throughput"
    echo "   figures below exclude them, so treat this run as suspect."
    echo "   Per-phase breakdown is in the report's err column."
else
    echo " no failed requests across the sweep"
fi
echo " report: ${REPORT}"
echo "═══════════════════════════════════════════════════════════════════"
