#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# Real-build sccache benchmark — the number that actually matters
#
# The synthetic bench (bench-sccache.sh) measures the proxy. This measures the
# thing users feel: how long a cargo build takes when sccache is backed by
# spiceio, and how much of that is the cache rather than the compiler.
#
# It runs the same build three ways and compares them:
#
#   nocache   RUSTC_WRAPPER unset — the compile-everything ceiling
#   local     sccache on local disk — the floor for a cache-hit build; the
#             fastest any backend could possibly make it
#   spiceio   sccache → spiceio → SMB — what we ship
#
# `local` is the point of the exercise. "Warm build takes 40s" means nothing on
# its own; "warm build takes 40s where local disk takes 12s" says the backend is
# adding 28s and names the target to beat.
#
# Metrics per arm, from sccache's own JSON stats (so they are the client's view,
# not ours):
#
#   wall clock            cold and warm build seconds
#   cache_read_hit_avg    mean time to fetch and unpack one hit
#   cache_write_avg       mean time to store one object
#   hit rate              hits / (hits + misses)
#   errors                read errors, write errors, timeouts
#
# The per-hit and per-write averages are the diagnostic: multiply by the object
# count and you know how much of the warm build is backend latency.
#
# Usage:
#   SPICEIO_SMB_USER=u SPICEIO_SMB_PASS=p ./scripts/bench-sccache-build.sh
#   BUILD_JOBS="4 16" BUILD_TARGET=~/dev/spiceai ./scripts/bench-sccache-build.sh
#
# Knobs:
#   BUILD_TARGET      repo to build (default: this repo)
#   BUILD_PACKAGE     -p argument for the target repo (default: none)
#   BUILD_CARGO_EXTRA extra cargo flags (e.g. "--all-targets --all-features")
#   BUILD_JOBS        space-separated cargo -j sweep (default "$(nproc)")
#   BUILD_ARMS        space-separated subset of "nocache local spiceio"
#   BENCH_SMB_CONNECTIONS  spiceio pool size (default 12)
#   BENCH_OUT         results directory (default benches/results)
#   BENCH_LABEL       label recorded in the report (default: git describe)
# ═══════════════════════════════════════════════════════════════════════════

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-sccache-bench}"
BIND="${SPICEIO_BIND:-127.0.0.1:18392}"
SMB_CONNS="${BENCH_SMB_CONNECTIONS:-12}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

BUILD_TARGET="${BUILD_TARGET:-$REPO_ROOT}"
BUILD_PACKAGE="${BUILD_PACKAGE:-}"
DEFAULT_JOBS="$(sysctl -n hw.ncpu 2>/dev/null || echo 8)"
JOBS_SWEEP="${BUILD_JOBS:-$DEFAULT_JOBS}"
ARMS="${BUILD_ARMS:-nocache local spiceio}"
OUT_DIR="${BENCH_OUT:-benches/results}"
SPICEIO_BIN="${SPICEIO_BIN:-./target/release/spiceio}"
ENDPOINT="http://${BIND}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
LABEL="${BENCH_LABEL:-$(git describe --always --dirty 2>/dev/null || echo unknown)}"
RESULTS="${OUT_DIR}/build-${RUN_ID}"
TMP="$(mktemp -d /tmp/spiceio-buildbench.XXXXXX)"

mkdir -p "$RESULTS"

# The ambient environment on this machine points sccache at a directory on the
# very share under test. Every arm sets its own backend explicitly; inheriting
# one would silently make three arms measure the same thing.
unset RUSTC_WRAPPER SCCACHE_DIR SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION \
    SCCACHE_S3_KEY_PREFIX SCCACHE_S3_USE_SSL SCCACHE_GCS_BUCKET SCCACHE_REDIS \
    SCCACHE_MEMCACHED SCCACHE_WEBDAV_ENDPOINT SCCACHE_AZURE_CONNECTION_STRING

if [[ ! -f "${BUILD_TARGET}/Cargo.toml" ]]; then
    echo "[bench] BUILD_TARGET ${BUILD_TARGET} has no Cargo.toml" >&2
    exit 1
fi
if ! command -v sccache >/dev/null 2>&1; then
    echo "[bench] sccache not installed" >&2
    exit 1
fi
# Rebuild rather than trust whatever is on disk — see bench-sccache.sh.
if [[ "$SPICEIO_BIN" == "./target/release/spiceio" ]]; then
    echo "[bench] building release binary..."
    cargo build --release --locked --quiet
elif [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[bench] SPICEIO_BIN ${SPICEIO_BIN} is not executable" >&2
    exit 1
fi

CARGO_ARGS=(build --quiet)
if [[ -n "$BUILD_PACKAGE" ]]; then
    CARGO_ARGS+=(-p "$BUILD_PACKAGE")
fi
# Extra cargo flags, e.g. BUILD_CARGO_EXTRA="--all-targets --all-features" to
# widen a small crate into enough compile units for the averages to mean
# something.
if [[ -n "${BUILD_CARGO_EXTRA:-}" ]]; then
    # shellcheck disable=SC2206  # deliberate word splitting: these are flags
    CARGO_ARGS+=(${BUILD_CARGO_EXTRA})
fi

BUILD_DIR="${TMP}/target"
LOCAL_CACHE="${TMP}/sccache-local"
S3_PREFIX_ROOT="buildbench/${RUN_ID}"
SPICEIO_PID=""

cleanup() {
    sccache --stop-server >/dev/null 2>&1 || true
    # A cold+warm build of a large workspace writes gigabytes; do not leave it
    # on a shared NAS. Needs the proxy still up, so this runs before the kill.
    if [[ -n "$SPICEIO_PID" ]] && command -v aws >/dev/null 2>&1; then
        echo "[bench] removing build-cache objects from the share..."
        aws --endpoint-url "$ENDPOINT" --no-sign-request --region "$REGION" \
            s3 rm "s3://${BUCKET}/${S3_PREFIX_ROOT}/" --recursive \
            >/dev/null 2>&1 || true
    fi
    if [[ -n "$SPICEIO_PID" ]]; then
        kill -TERM "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP"
}
trap cleanup EXIT

start_spiceio() {
    # Keep the proxy log with the results, not in TMP: when the run turns up
    # failed cache writes, this log is the only place the reason is recorded,
    # and the EXIT trap deletes TMP before anyone can look.
    local log="${RESULTS}/spiceio.log"
    local port="${BIND##*:}" stale
    stale="$(lsof -i ":${port}" -sTCP:LISTEN -t 2>/dev/null || true)"
    if [[ -n "$stale" ]]; then
        kill $stale 2>/dev/null || true
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
    SPICEIO_SMB_CONNECTIONS="$SMB_CONNS" \
    SPICEIO_LOG_FILE="$log" \
    SPICEIO_ACCESS_LOG="${RESULTS}/access-build.tsv" \
        "$SPICEIO_BIN" >/dev/null 2>&1 &
    SPICEIO_PID=$!
    local i
    for i in $(seq 1 120); do
        grep -q 'ready, listening on' "$log" 2>/dev/null && return 0
        if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
            echo "[bench] spiceio failed to start:" >&2
            tail -20 "$log" >&2 2>/dev/null || true
            return 1
        fi
        sleep 0.5
    done
    echo "[bench] spiceio not ready within 60s" >&2
    return 1
}

# Point sccache at one backend. Each arm gets a fresh server: sccache reads its
# backend config once at startup, so reconfiguring a running server is silently
# a no-op — and the arms would all report the first arm's backend.
configure_sccache() {
    local arm="$1" jobs="$2"
    sccache --stop-server >/dev/null 2>&1 || true
    unset SCCACHE_DIR SCCACHE_BUCKET SCCACHE_ENDPOINT SCCACHE_REGION \
        SCCACHE_S3_KEY_PREFIX SCCACHE_S3_USE_SSL RUSTC_WRAPPER
    case "$arm" in
        local)
            rm -rf "$LOCAL_CACHE"
            export SCCACHE_DIR="$LOCAL_CACHE"
            export SCCACHE_CACHE_SIZE="50G"
            ;;
        spiceio)
            export SCCACHE_BUCKET="$BUCKET"
            export SCCACHE_ENDPOINT="$ENDPOINT"
            export SCCACHE_REGION="$REGION"
            export SCCACHE_S3_USE_SSL=false
            # Unique per (arm, jobs): a shared prefix would leave the second
            # jobs value with a populated cache, and its "cold" build would
            # silently be a warm one.
            export SCCACHE_S3_KEY_PREFIX="${S3_PREFIX_ROOT}/j${jobs}"
            export AWS_ACCESS_KEY_ID=test
            export AWS_SECRET_ACCESS_KEY=test
            ;;
        nocache)
            # No wrapper at all — cargo invokes rustc directly.
            return 0
            ;;
    esac
    export RUSTC_WRAPPER=sccache
    sccache --start-server >/dev/null 2>&1
    sccache --zero-stats >/dev/null 2>&1 || true
}

# Extract the client-side metrics from sccache's JSON stats.
#   hits misses writes read_errors write_errors timeouts hit_avg_ms write_avg_ms
sccache_metrics() {
    sccache --show-stats --stats-format json 2>/dev/null | python3 -c '
import json, sys
try:
    doc = json.load(sys.stdin)["stats"]
except Exception:
    print("0 0 0 0 0 0 0.0 0.0"); raise SystemExit
def total(field):
    v = doc.get(field) or {}
    counts = v.get("counts") if isinstance(v, dict) else None
    return sum(counts.values()) if counts else 0
def dur_ms(field):
    d = doc.get(field) or {}
    return d.get("secs", 0) * 1000.0 + d.get("nanos", 0) / 1e6
hits, misses = total("cache_hits"), total("cache_misses")
writes = doc.get("cache_writes", 0)
# sccache reports cumulative durations; per-op averages are what compare across
# backends, since the op counts differ between a cold and a warm build.
hit_avg = dur_ms("cache_read_hit_duration") / hits if hits else 0.0
write_avg = dur_ms("cache_write_duration") / writes if writes else 0.0
print(hits, misses, writes,
      doc.get("cache_read_errors", 0), doc.get("cache_write_errors", 0),
      doc.get("cache_timeouts", 0), f"{hit_avg:.2f}", f"{write_avg:.2f}")
'
}

# run_build <jobs> -> seconds
#
# Build output goes to a file rather than /dev/null: a benchmark that reports
# only "build failed" is unusable, and the failure is usually a property of the
# target repo (missing toolchain, feature that needs a system library) that the
# tail makes obvious.
run_build() {
    local jobs="$1" start end log="${TMP}/build.log"
    rm -rf "$BUILD_DIR"
    start=$(python3 -c 'import time;print(time.time())')
    # Build from inside the target repo rather than via --manifest-path: cargo
    # resolves rust-toolchain.toml and .cargo/config.toml from the working
    # directory, so --manifest-path silently builds a pinned repo with the
    # wrong toolchain. CARGO_TARGET_DIR is absolute, so the cd is safe.
    if ! (cd "$BUILD_TARGET" && CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$BUILD_DIR" \
        cargo "${CARGO_ARGS[@]}" -j "$jobs") >"$log" 2>&1; then
        echo "[bench] build failed (jobs=${jobs}); last 30 lines:" >&2
        tail -30 "$log" >&2 2>/dev/null || true
        cp "$log" "${RESULTS}/build-failure.log" 2>/dev/null || true
        return 1
    fi
    end=$(python3 -c 'import time;print(time.time())')
    python3 -c "print(f'{$end-$start:.1f}')"
}

TSV="${RESULTS}/build-results.tsv"
printf 'arm\tjobs\tphase\tsecs\thits\tmisses\twrites\tread_err\twrite_err\ttimeouts\thit_avg_ms\twrite_avg_ms\n' >"$TSV"

echo "═══════════════════════════════════════════════════════════════════"
echo " spiceio real-build sccache bench — ${LABEL}"
echo " build  : ${BUILD_TARGET}${BUILD_PACKAGE:+ (-p ${BUILD_PACKAGE})}"
echo " arms   : ${ARMS}"
echo " jobs   : ${JOBS_SWEEP}"
echo " target : smb://${SMB_SERVER}/${SMB_SHARE}  bucket=${BUCKET}"
echo " results: ${RESULTS}"
echo "═══════════════════════════════════════════════════════════════════"

NEEDS_PROXY=0
for arm in $ARMS; do
    [[ "$arm" == "spiceio" ]] && NEEDS_PROXY=1
done
if [[ "$NEEDS_PROXY" == "1" ]]; then
    echo "[bench] starting spiceio (pool=${SMB_CONNS})..."
    start_spiceio
fi

for arm in $ARMS; do
    for jobs in $JOBS_SWEEP; do
        echo ""
        echo "── arm=${arm} jobs=${jobs} ─────────────────────────────────────"
        configure_sccache "$arm" "$jobs"

        if [[ "$arm" == "nocache" ]]; then
            # No cache to populate, so there is no cold/warm distinction — one
            # build is the compile-everything ceiling both other arms race.
            secs="$(run_build "$jobs")"
            echo "  build: ${secs}s (no cache)"
            printf '%s\t%s\tfull\t%s\t0\t0\t0\t0\t0\t0\t0.00\t0.00\n' \
                "$arm" "$jobs" "$secs" >>"$TSV"
            continue
        fi

        # Cold: populate. Every compile is a miss followed by a cache write, so
        # this is the arm's write path under full build concurrency.
        sccache --zero-stats >/dev/null 2>&1 || true
        cold="$(run_build "$jobs")"
        read -r c_hits c_miss c_writes c_rerr c_werr c_to c_hitavg c_wravg < <(sccache_metrics)
        printf '%s\t%s\tcold\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$arm" "$jobs" "$cold" "$c_hits" "$c_miss" "$c_writes" \
            "$c_rerr" "$c_werr" "$c_to" "$c_hitavg" "$c_wravg" >>"$TSV"
        echo "  cold: ${cold}s  misses=${c_miss} writes=${c_writes} write_avg=${c_wravg}ms write_err=${c_werr}"

        # Warm: the build users actually wait on. Read path only.
        sccache --zero-stats >/dev/null 2>&1 || true
        warm="$(run_build "$jobs")"
        read -r w_hits w_miss w_writes w_rerr w_werr w_to w_hitavg w_wravg < <(sccache_metrics)
        printf '%s\t%s\twarm\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$arm" "$jobs" "$warm" "$w_hits" "$w_miss" "$w_writes" \
            "$w_rerr" "$w_werr" "$w_to" "$w_hitavg" "$w_wravg" >>"$TSV"
        echo "  warm: ${warm}s  hits=${w_hits} misses=${w_miss} hit_avg=${w_hitavg}ms read_err=${w_rerr} timeouts=${w_to}"

        sccache --show-stats >"${RESULTS}/stats-${arm}-j${jobs}-warm.txt" 2>&1 || true
    done
done

sccache --stop-server >/dev/null 2>&1 || true

# ── Report ────────────────────────────────────────────────────────────────

REPORT="${RESULTS}/report.md"
python3 - "$TSV" "$REPORT" "$LABEL" "$BUILD_TARGET" "$BUILD_PACKAGE" <<'PY'
import sys, csv, os

tsv, out, label, target, package = sys.argv[1:6]
rows = list(csv.DictReader(open(tsv), delimiter="\t"))
def f(r, k):
    try: return float(r[k])
    except (ValueError, KeyError): return 0.0

lines = []
w = lines.append
w(f"# spiceio real-build sccache bench — {os.path.basename(os.path.dirname(out))}")
w("")
w("| field | value |")
w("| --- | --- |")
w(f"| label | `{label}` |")
w(f"| build | `{target}`{f' (-p {package})' if package else ''} |")
w("")
w("`local` is sccache on local disk — the floor a network backend is measured")
w("against. `nocache` is the compile-everything ceiling.")
w("")
w("| arm | jobs | phase | wall | hits | misses | hit avg | write avg | errors |")
w("| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
for r in rows:
    errs = int(f(r, "read_err") + f(r, "write_err") + f(r, "timeouts"))
    w(f"| {r['arm']} | {r['jobs']} | {r['phase']} | {f(r,'secs'):.1f}s "
      f"| {int(f(r,'hits'))} | {int(f(r,'misses'))} "
      f"| {f(r,'hit_avg_ms'):.2f}ms | {f(r,'write_avg_ms'):.2f}ms | {errs} |")
w("")

# The comparison the whole script exists for.
by = {}
for r in rows:
    by[(r["arm"], r["jobs"], r["phase"])] = r
jobs_list = sorted({r["jobs"] for r in rows}, key=int)
w("## spiceio versus local disk")
w("")
w("| jobs | phase | local | spiceio | overhead | per-op gap |")
w("| ---: | --- | ---: | ---: | ---: | --- |")
for j in jobs_list:
    for phase in ("cold", "warm"):
        lo, sp = by.get(("local", j, phase)), by.get(("spiceio", j, phase))
        if not lo or not sp:
            continue
        ls, ss = f(lo, "secs"), f(sp, "secs")
        ratio = (ss / ls) if ls else 0.0
        if phase == "warm":
            gap = (f(sp, "hit_avg_ms") - f(lo, "hit_avg_ms"))
            gapdesc = f"+{gap:.2f}ms per cache hit"
        else:
            gap = (f(sp, "write_avg_ms") - f(lo, "write_avg_ms"))
            gapdesc = f"+{gap:.2f}ms per cache write"
        w(f"| {j} | {phase} | {ls:.1f}s | {ss:.1f}s | {ratio:.2f}x | {gapdesc} |")
w("")
nc = [r for r in rows if r["arm"] == "nocache"]
if nc:
    w("## Cache value")
    w("")
    w("| jobs | no cache | spiceio warm | saved |")
    w("| ---: | ---: | ---: | ---: |")
    for j in jobs_list:
        full = by.get(("nocache", j, "full"))
        sp = by.get(("spiceio", j, "warm"))
        if not full or not sp:
            continue
        fs, ss = f(full, "secs"), f(sp, "secs")
        w(f"| {j} | {fs:.1f}s | {ss:.1f}s | {(1 - ss/fs)*100 if fs else 0:.0f}% |")
    w("")
w("## Raw")
w("")
w(f"- `{os.path.basename(tsv)}` — every measurement, tab separated")
w("- `stats-<arm>-j<jobs>-warm.txt` — full `sccache --show-stats` per arm")
w("- `access-build.tsv` — spiceio server-side per-request log for the spiceio arm")
open(out, "w").write("\n".join(lines) + "\n")
PY

echo ""
echo "═══════════════════════════════════════════════════════════════════"
cat "$REPORT"
echo "═══════════════════════════════════════════════════════════════════"
echo " report: ${REPORT}"
