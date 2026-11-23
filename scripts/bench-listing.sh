#!/bin/sh
# What a ListObjectsV2 first page costs, by max-keys and by the size of the
# prefix under it. A measurement, not a gate: `make ci` never runs it.
#
#   BENCH_BUCKET=<bucket> scripts/bench-listing.sh
#
# For each size in BENCH_SIZES it creates that many one-byte objects under a
# fresh prefix (20 directories each), then lists each prefix with max-keys=1
# and max-keys=1000, alternating sizes and repeating BENCH_REPS times, so
# drift on a shared NAS spreads across every arm. It prints each arm's median
# with every run beside it. The objects are deleted on exit; their empty
# directories stay on the share (DeleteObject does not remove a directory it
# empties).
#
# If a first page cost what it returns, max-keys=1 would be flat across
# sizes. If it walks the whole prefix first, max-keys=1 tracks max-keys=1000
# and grows with the prefix.
#
# Settings (environment):
#   BENCH_ENDPOINT   default http://127.0.0.1:8333 (the launchd agent)
#   BENCH_BUCKET     required: the bucket (spiceio's SPICEIO_BUCKET, which
#                    defaults to the share name)
#   BENCH_SIZES      default "200 2000"
#   BENCH_REPS       default 3
#   SPICEIO_CLIENT_CREDENTIALS_FILE  the key to sign with (default
#                    ~/.config/spiceio/credentials; its last key, as
#                    sccache-spiceio uses). Unsigned if the file does not exist.
#
# The secret only reaches curl on stdin (`-K -`), never an argument list or
# the output. Results also go to benches/results/listing-<time>.txt.
set -eu

ENDPOINT="${BENCH_ENDPOINT:-http://127.0.0.1:8333}"
CREDS="${SPICEIO_CLIENT_CREDENTIALS_FILE:-$HOME/.config/spiceio/credentials}"

# req METHOD PATH [curl args...]: one request, signed when there is a key.
req() {
    m=$1
    p=$2
    shift 2
    if [ -r "$CREDS" ]; then
        awk '!/^#/ && NF >= 2 {k = $1; s = $2} END {if (k != "") print "user = \"" k ":" s "\""}' "$CREDS" |
            curl -q --noproxy '*' -s --max-time 600 -K - --aws-sigv4 'aws:amz:us-east-1:s3' \
                -X "$m" "$@" "$ENDPOINT$p"
    else
        curl -q --noproxy '*' -s --max-time 600 -X "$m" "$@" "$ENDPOINT$p"
    fi
}

# `--req METHOD PATH [curl args...]`: what the parallel PUTs and DELETEs run.
if [ "${1:-}" = --req ]; then
    shift
    req "$@"
    exit
fi

BUCKET="${BENCH_BUCKET:?BENCH_BUCKET is required (the bucket to create test objects in)}"
SIZES="${BENCH_SIZES:-200 2000}"
REPS="${BENCH_REPS:-3}"
DIRS=20
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-bench-listing.XXXXXX")
PREFIX="spiceio-bench-listing-$(python3 -I -c 'import secrets; print(secrets.token_hex(4))')"
mkdir -p "$ROOT/benches/results"
OUT="$ROOT/benches/results/listing-$(date +%Y%m%d-%H%M%S).txt"

cleanup() {
    if [ -s "$WORK/keys" ]; then
        echo "deleting the $(wc -l <"$WORK/keys" | tr -d ' ') test objects under $PREFIX/"
        sed "s#^#/$BUCKET/#" "$WORK/keys" |
            xargs -P 16 -I{} sh "$SELF" --req DELETE {} -o /dev/null -w '%{http_code}\n' |
            sort | uniq -c | sed 's/^/  DELETE /'
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

: >"$WORK/keys"
for size in $SIZES; do
    per=$(((size + DIRS - 1) / DIRS))
    n=0
    d=0
    while [ "$n" -lt "$size" ]; do
        f=0
        while [ "$f" -lt "$per" ] && [ "$n" -lt "$size" ]; do
            printf '%s/%s/d%02d/f%05d\n' "$PREFIX" "$size" "$d" "$f" >>"$WORK/keys"
            f=$((f + 1))
            n=$((n + 1))
        done
        d=$((d + 1))
    done
done
echo "creating $(wc -l <"$WORK/keys" | tr -d ' ') objects under $ENDPOINT/$BUCKET/$PREFIX/"
sed "s#^#/$BUCKET/#" "$WORK/keys" |
    xargs -P 16 -I{} sh "$SELF" --req PUT {} --data-binary x -o /dev/null -w '%{http_code}\n' |
    sort | uniq -c | sed 's/^/  PUT /'

{
    echo "# $(date -u +%FT%TZ) $ENDPOINT/$BUCKET, sizes: $SIZES, reps: $REPS"
    rep=1
    while [ "$rep" -le "$REPS" ]; do
        for size in $SIZES; do
            for mk in 1 1000; do
                r=$(req GET "/$BUCKET?list-type=2&max-keys=$mk&prefix=$PREFIX/$size/" \
                    -o "$WORK/body" -w '%{http_code} %{time_total}')
                keys=$(grep -o '<Key>' "$WORK/body" | wc -l | tr -d ' ')
                echo "rep$rep size=$size max-keys=$mk status=${r% *} seconds=${r#* } keys=$keys"
            done
        done
        rep=$((rep + 1))
    done
} | tee "$OUT"

python3 -I - "$OUT" <<'EOF'
import collections, statistics, sys
runs = collections.defaultdict(list)
for line in open(sys.argv[1]):
    if line.startswith("#"):
        continue
    f = dict(kv.split("=", 1) for kv in line.split()[1:])
    runs[(int(f["size"]), int(f["max-keys"]))].append(float(f["seconds"]))
print(f"{'size':>8} {'max-keys':>9} {'median s':>9}  runs")
for (size, mk), v in sorted(runs.items()):
    print(f"{size:>8} {mk:>9} {statistics.median(v):>9.3f}  {', '.join(f'{x:.3f}' for x in v)}")
EOF
echo "results: $OUT"
