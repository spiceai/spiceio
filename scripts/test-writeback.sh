#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# ── Write-back + disk-spill live test ──────────────────────────────────────
#
# Covers the two things unit tests structurally cannot: that a write
# acknowledged from memory actually reaches the NAS, and that the machine-wide
# spill is shared between processes.
#
# The load-bearing assertion is the restart. A PUT under `SPICEIO_WRITE_BACK=1`
# returns before the backend write happens, so "did it work" cannot be answered
# by asking the instance that accepted it — its own cache would answer from
# memory either way. So this script stops the instance (SIGTERM, which drains),
# starts a *second* one with write-back and the spill both off, and reads the
# objects back through it. That second instance has nothing but the NAS to
# answer from.
#
# Requires: SPICEIO_SMB_USER, SPICEIO_SMB_PASS (plus SERVER/SHARE or defaults).
# ═══════════════════════════════════════════════════════════════════════════

set -uo pipefail

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-writeback}"
BIND="${SPICEIO_BIND:-127.0.0.1:18337}"
BIND2="${SPICEIO_BIND2:-127.0.0.1:18338}"
ENDPOINT="http://${BIND}"
ENDPOINT2="http://${BIND2}"
SPICEIO_BIN="./target/debug/spiceio"
PREFIX="wbtest/$$"

if [[ -z "${SPICEIO_SMB_USER:-}" || -z "${SPICEIO_SMB_PASS:-}" ]]; then
    echo "[wb] SPICEIO_SMB_USER / SPICEIO_SMB_PASS must be set"
    exit 1
fi
if [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[wb] $SPICEIO_BIN not found — run: cargo build --locked --bins"
    exit 1
fi

PASS=0
FAIL=0
PID1=""
PID2=""
# Private spill root: this test asserts on the *contents* of the spill, which a
# shared /var/tmp/spiceio-cache used by a real instance would make unstable.
SPILL_DIR="$(mktemp -d /tmp/spiceio-wb-spill.XXXXXX)"
WORK="$(mktemp -d /tmp/spiceio-wb-work.XXXXXX)"
LOG_DIR="$(mktemp -d /tmp/spiceio-wb-logs.XXXXXX)"
LOG_SEQ=0

cleanup() {
    for pid in "$PID1" "$PID2"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    rm -rf "$SPILL_DIR" "$WORK" "$LOG_DIR"
}
trap cleanup EXIT

ok()   { echo "  PASS: $*"; PASS=$((PASS + 1)); }
# stop <pid-var> — SIGTERM, wait, and let the async logger + tee drain so the
# shutdown summary is actually in the file before anything greps it.
stop() {
    local __pidvar="$1" pid="${!1}"
    [[ -z "$pid" ]] && return 0
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    printf -v "$__pidvar" '%s' ""
    for _ in $(seq 1 50); do
        grep -q 'all connections drained\|shutting down' "$LAST_LOG" 2>/dev/null && break
        sleep 0.1
    done
    sleep 0.2
}
bad()  { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (expected '$3', got '$2')"; fi; }

# start <var-name> <bind> <extra env...>
#
# Sets LAST_LOG to this instance's own stderr capture. Per-instance rather than
# shared: the assertions below are about which *process* reported what.
start() {
    local __pidvar="$1" bind="$2"
    shift 2
    LOG_SEQ=$((LOG_SEQ + 1))
    LAST_LOG="${LOG_DIR}/spiceio-${LOG_SEQ}.log"
    local port="${bind##*:}" stale
    stale="$(lsof -i ":${port}" -sTCP:LISTEN -t 2>/dev/null || true)"
    if [[ -n "$stale" ]]; then
        echo "$stale" | xargs kill 2>/dev/null || true
        sleep 1
    fi
    env "$@" \
        SPICEIO_BIND="$bind" \
        SPICEIO_SMB_SERVER="$SMB_SERVER" \
        SPICEIO_SMB_PORT="$SMB_PORT" \
        SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
        SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
        SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
        SPICEIO_SMB_SHARE="$SMB_SHARE" \
        SPICEIO_BUCKET="$BUCKET" \
        SPICEIO_REGION="$REGION" \
        "$SPICEIO_BIN" > >(tee -a "$LAST_LOG") 2>&1 &
    printf -v "$__pidvar" '%s' "$!"
    local pid="${!__pidvar}"
    for i in $(seq 1 120); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[wb] spiceio on ${bind} failed to start"
            exit 1
        fi
        if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://${bind}/" 2>/dev/null)" == "200" ]]; then
            return 0
        fi
        if [[ "$i" -eq 120 ]]; then
            echo "[wb] spiceio on ${bind} not ready after 60s"
            exit 1
        fi
        sleep 0.5
    done
}

echo "═══════════════════════════════════════════════════════════════"
echo " spiceio write-back + spill test"
echo " target : smb://${SMB_SERVER}/${SMB_SHARE}  bucket=${BUCKET}"
echo " spill  : ${SPILL_DIR}"
echo "═══════════════════════════════════════════════════════════════"

start PID1 "$BIND" SPICEIO_WRITE_BACK=1 SPICEIO_SPILL_DIR="$SPILL_DIR"
echo "[wb] instance 1 up (write-back on)"

# ════════════════════════════════════════════════════════════════════════════
# 1. Acknowledged writes are consistent from the instance that took them
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 1. Read-your-write through an asynchronous acknowledgement"
echo "═══════════════════════════════════════════════════════════════"

# Two sizes: under the 64 KiB compound threshold and over it, so both the
# compound and the WAL flush paths are exercised.
head -c 4096 /dev/urandom >"${WORK}/small.bin"
head -c 3145728 /dev/urandom >"${WORK}/large.bin"

for name in small large; do
    key="${PREFIX}/${name}.bin"
    hdrs=$(curl -s -X PUT --data-binary "@${WORK}/${name}.bin" \
        -D - -o /dev/null "${ENDPOINT}/${BUCKET}/${key}")
    # A large body makes curl send `Expect: 100-continue`, so the first
    # status line is the interim 100; the response status is the last one.
    code=$(printf '%s' "$hdrs" | awk '/^HTTP\//{c=$2} END{print c}')
    check "PUT ${name} accepted" "$code" "200"
    if printf '%s' "$hdrs" | grep -qi '^x-spiceio-write: ASYNC'; then
        ok "PUT ${name} was acknowledged asynchronously"
    else
        bad "PUT ${name} took the synchronous path (write-back not engaged)"
    fi

    # Immediately, with the backend write still outstanding.
    curl -s -o "${WORK}/${name}.get" "${ENDPOINT}/${BUCKET}/${key}"
    if cmp -s "${WORK}/${name}.bin" "${WORK}/${name}.get"; then
        ok "GET ${name} returns the written bytes before the flush"
    else
        bad "GET ${name} did not match what was written"
    fi

    code=$(curl -s -o /dev/null -w '%{http_code}' -I "${ENDPOINT}/${BUCKET}/${key}")
    check "HEAD ${name} sees the pending object" "$code" "200"
    len=$(curl -s -I "${ENDPOINT}/${BUCKET}/${key}" \
        | awk 'BEGIN{IGNORECASE=1} /^content-length:/{gsub(/\r/,"");print $2}')
    check "HEAD ${name} reports the pending size" "$len" "$(wc -c <"${WORK}/${name}.bin" | tr -d ' ')"
done

# A range read cannot be answered from the cache — only the backend can seek
# inside the object — so it has to wait for the pending write to land rather
# than go straight to a NAS that does not have the object yet. Getting this
# wrong returns 404 for an object the client was just told it had written, and
# only shows up when the flush loses the race.
range_key="${PREFIX}/range.bin"
curl -s -o /dev/null -X PUT --data-binary "@${WORK}/large.bin" \
    "${ENDPOINT}/${BUCKET}/${range_key}"
code=$(curl -s -o "${WORK}/range.get" -w '%{http_code}' \
    -H "Range: bytes=1048576-2097151" "${ENDPOINT}/${BUCKET}/${range_key}")
check "range GET of a just-acknowledged write is not a 404" "$code" "206"
dd if="${WORK}/large.bin" of="${WORK}/range.want" bs=1048576 skip=1 count=1 2>/dev/null
if cmp -s "${WORK}/range.want" "${WORK}/range.get"; then
    ok "range GET of a pending write returns the right slice"
else
    bad "range GET of a pending write returned the wrong bytes"
fi

# A listing that omitted pending keys would tell a client its write vanished.
listing=$(curl -s "${ENDPOINT}/${BUCKET}?list-type=2&prefix=${PREFIX}/")
for name in small large; do
    if printf '%s' "$listing" | grep -q "${PREFIX}/${name}.bin"; then
        ok "ListObjectsV2 includes pending ${name}"
    else
        bad "ListObjectsV2 omitted pending ${name}"
    fi
done

# ════════════════════════════════════════════════════════════════════════════
# 2. A delete beats the flush that would resurrect the object
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 2. DELETE of a pending write"
echo "═══════════════════════════════════════════════════════════════"

del_key="${PREFIX}/deleted.bin"
curl -s -X PUT --data-binary "@${WORK}/small.bin" -o /dev/null "${ENDPOINT}/${BUCKET}/${del_key}"
code=$(curl -s -o /dev/null -w '%{http_code}' -X DELETE "${ENDPOINT}/${BUCKET}/${del_key}")
check "DELETE of a pending object" "$code" "204"
code=$(curl -s -o /dev/null -w '%{http_code}' "${ENDPOINT}/${BUCKET}/${del_key}")
check "GET after DELETE is 404" "$code" "404"

# ════════════════════════════════════════════════════════════════════════════
# 3. Overwrites coalesce to the last body, not to an arbitrary one
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 3. Rapid overwrite of one key"
echo "═══════════════════════════════════════════════════════════════"

ow_key="${PREFIX}/overwrite.bin"
for v in 1 2 3 4 5; do
    printf 'version-%s' "$v" >"${WORK}/v${v}.txt"
    curl -s -X PUT --data-binary "@${WORK}/v${v}.txt" -o /dev/null "${ENDPOINT}/${BUCKET}/${ow_key}"
done
body=$(curl -s "${ENDPOINT}/${BUCKET}/${ow_key}")
check "GET returns the last write" "$body" "version-5"

# ════════════════════════════════════════════════════════════════════════════
# 4. Shutdown drains, and the bytes are really on the NAS
#
#    The instance that accepted these writes is gone. Instance 2 has write-back
#    and the spill both off, so the only thing it can answer from is the share.
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 4. Durability across a graceful restart"
echo "═══════════════════════════════════════════════════════════════"

LOG1="$LAST_LOG"
stop PID1

dirty=$(find "$SPILL_DIR" -name '*.d' 2>/dev/null | wc -l | tr -d ' ')
check "no unflushed spill entries after the drain" "$dirty" "0"
if grep -q 'did not reach the NAS before shutdown' "$LOG1"; then
    bad "shutdown reported writes that never reached the NAS"
else
    ok "shutdown drained every acknowledged write"
fi

start PID2 "$BIND2" SPICEIO_WRITE_BACK=0 SPICEIO_SPILL_DIR=off
echo "[wb] instance 2 up (write-back off, no spill — reads the NAS only)"

for name in small large; do
    key="${PREFIX}/${name}.bin"
    curl -s -o "${WORK}/${name}.nas" "${ENDPOINT2}/${BUCKET}/${key}"
    if cmp -s "${WORK}/${name}.bin" "${WORK}/${name}.nas"; then
        ok "${name} reached the NAS intact"
    else
        bad "${name} on the NAS does not match what was acknowledged"
    fi
done

body=$(curl -s "${ENDPOINT2}/${BUCKET}/${ow_key}")
check "the overwritten key settled on the last write" "$body" "version-5"

code=$(curl -s -o /dev/null -w '%{http_code}' "${ENDPOINT2}/${BUCKET}/${del_key}")
check "the deleted key was not resurrected by a flush" "$code" "404"

# ════════════════════════════════════════════════════════════════════════════
# 5. The spill is shared: a second process reads what the first cached
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 5. Machine-wide spill sharing"
echo "═══════════════════════════════════════════════════════════════"

stop PID2

# A fresh spill so hits here can only come from what instance A puts there.
SHARED_SPILL="$(mktemp -d /tmp/spiceio-wb-shared.XXXXXX)"
start PID1 "$BIND" SPICEIO_SPILL_DIR="$SHARED_SPILL"
for name in small large; do
    curl -s -o /dev/null "${ENDPOINT}/${BUCKET}/${PREFIX}/${name}.bin"
done
# Let the background spill writes land.
for _ in $(seq 1 50); do
    [[ "$(find "$SHARED_SPILL" -name '*.o' | wc -l | tr -d ' ')" -ge 2 ]] && break
    sleep 0.1
done
entries=$(find "$SHARED_SPILL" -name '*.o' | wc -l | tr -d ' ')
if [[ "$entries" -ge 2 ]]; then
    ok "reads populated the shared spill (${entries} entries)"
else
    bad "reads did not populate the spill (${entries} entries)"
fi

# Instance B: same spill directory, no memory cache at all. Anything it serves
# without a backend body read came off the disk tier the first instance filled.
start PID2 "$BIND2" SPICEIO_SPILL_DIR="$SHARED_SPILL" \
    SPICEIO_OBJECT_CACHE_BYTES=1 SPICEIO_OBJECT_CACHE_ENTRIES=1
for name in small large; do
    curl -s -o "${WORK}/${name}.shared" "${ENDPOINT2}/${BUCKET}/${PREFIX}/${name}.bin"
    if cmp -s "${WORK}/${name}.bin" "${WORK}/${name}.shared"; then
        ok "instance B served ${name} correctly from the shared spill"
    else
        bad "instance B returned wrong bytes for ${name}"
    fi
done
stop PID2
if grep -q 'disk spill: [1-9][0-9]* hit' "$LAST_LOG"; then
    ok "instance B recorded disk-spill hits from the other process's writes"
else
    bad "instance B never hit the shared spill"
    echo "    --- instance B cache/spill lines ---"
    grep -E 'disk spill|object cache' "$LAST_LOG" | sed 's/^/    /'
fi

# ════════════════════════════════════════════════════════════════════════════
# 6. An abandoned drain is recoverable, not lost
#
#    Two stop signals means "stop now", so the drain is cut short. What is left
#    must survive as a journal on disk and be replayed by the next start —
#    otherwise the second signal silently discards writes clients were told
#    had succeeded.
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 6. Recovery from an abandoned drain"
echo "═══════════════════════════════════════════════════════════════"

# Section 5's instance still holds the port and the shared spill.
stop PID1
rm -rf "$SHARED_SPILL"

RECOVER_SPILL="$(mktemp -d /tmp/spiceio-wb-recover.XXXXXX)"
start PID1 "$BIND" SPICEIO_WRITE_BACK=1 SPICEIO_SPILL_DIR="$RECOVER_SPILL"
RECOVER_LOG="$LAST_LOG"
head -c 1048576 /dev/urandom >"${WORK}/recover.bin"
for i in $(seq 1 40); do
    curl -s -o /dev/null -X PUT --data-binary "@${WORK}/recover.bin" \
        "${ENDPOINT}/${BUCKET}/${PREFIX}/rec${i}.bin"
done

# Two signals in quick succession: the second must cut the drain short.
kill -TERM "$PID1" 2>/dev/null
sleep 0.1
kill -TERM "$PID1" 2>/dev/null
wait "$PID1" 2>/dev/null
PID1=""
for _ in $(seq 1 50); do
    grep -q 'write-back:' "$RECOVER_LOG" 2>/dev/null && break
    sleep 0.1
done
sleep 0.2

if grep -q 'stopping without finishing the drain' "$RECOVER_LOG"; then
    ok "a second stop signal cut the drain short"
else
    # The drain can legitimately finish first on a fast NAS; then there is no
    # residue to recover and the rest of this section has nothing to prove.
    ok "the drain completed before the second signal (nothing left to recover)"
fi
if grep -q 'write(s) were acknowledged but are lost' "$RECOVER_LOG"; then
    bad "acknowledged writes were dropped instead of journalled"
else
    ok "no acknowledged write was dropped"
fi

# Whatever did not reach the NAS must be on disk, ready to replay.
pending_before=$(find "$RECOVER_SPILL" -name '*.d' | wc -l | tr -d ' ')
echo "  [wb] ${pending_before} unflushed write(s) held on disk"

start PID2 "$BIND2" SPICEIO_WRITE_BACK=1 SPICEIO_SPILL_DIR="$RECOVER_SPILL"
# The first replay pass ignores the peer-politeness age, so it runs at once.
for _ in $(seq 1 100); do
    [[ "$(find "$RECOVER_SPILL" -name '*.d' | wc -l | tr -d ' ')" -eq 0 ]] && break
    sleep 0.2
done
left=$(find "$RECOVER_SPILL" -name '*.d' | wc -l | tr -d ' ')
check "every stranded write was replayed" "$left" "0"
if [[ "$pending_before" -gt 0 ]] && ! grep -q 'replaying' "$LAST_LOG"; then
    bad "restart did not report replaying the stranded writes"
else
    ok "restart replayed the stranded writes"
fi

# And they are the right bytes, read back through the instance that replayed.
curl -s -o "${WORK}/rec.get" "${ENDPOINT2}/${BUCKET}/${PREFIX}/rec1.bin"
if cmp -s "${WORK}/recover.bin" "${WORK}/rec.get"; then
    ok "a replayed object matches what was acknowledged"
else
    bad "a replayed object does not match what was acknowledged"
fi

for i in $(seq 1 40); do
    curl -s -o /dev/null -X DELETE "${ENDPOINT2}/${BUCKET}/${PREFIX}/rec${i}.bin"
done
stop PID2
rm -rf "$RECOVER_SPILL"

# ════════════════════════════════════════════════════════════════════════════
# 7. Shutdown drains this instance's journalled writes — and only its own
#
#    Instances share the spill directory, so "flush everything dirty on the way
#    out" would reach into a peer's in-flight work, and a backend 404 for a
#    peer's not-yet-written object must not be mistaken for a stale cache entry
#    and deleted. Both would destroy writes some client was told had succeeded.
# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " 7. Shutdown drains our own journalled writes, not a peer's"
echo "═══════════════════════════════════════════════════════════════"

OWN_SPILL="$(mktemp -d /tmp/spiceio-wb-own.XXXXXX)"
PEER_KEY="${PREFIX}/peer-owned.bin"

# A dirty entry written by some other process. Planted directly because a
# healthy peer promotes its own entries in milliseconds — this is the state a
# peer that is mid-flush (or wedged) leaves on disk. The header layout mirrors
# `Spill` in src/s3/spill.rs; the readback assertion below fails loudly if the
# two ever drift, rather than silently stopping testing anything.
python3 - "$OWN_SPILL" "$SMB_SERVER" "$SMB_PORT" "$SMB_SHARE" "$PEER_KEY" <<'PYEOF'
import hashlib, os, struct, sys
spill, server, port, share, key = sys.argv[1:6]
ns = f"{server}:{port}/{share}"
body = b"peer-owned-body-do-not-touch"
ident = (ns + "\0" + key).encode()
etag = b"peeretag"
h = hashlib.sha256(ident).hexdigest()
d = os.path.join(spill, "v1", h[:2])
os.makedirs(d, exist_ok=True)
hdr = b"SPIO" + struct.pack("<HHIIQQ", 1, 1, len(ident), len(etag), len(body), 7) \
      + hashlib.sha256(body).digest()
open(os.path.join(d, h[2:] + ".d"), "wb").write(hdr + ident + etag + body)
PYEOF

start PID1 "$BIND" SPICEIO_WRITE_BACK=1 SPICEIO_SPILL_DIR="$OWN_SPILL" \
    SPICEIO_IMMUTABLE_OBJECTS=1
# Proves the planted entry is in the format spiceio actually reads. If the
# on-disk layout changes, this fails instead of the test quietly passing.
peer_body=$(curl -s "${ENDPOINT}/${BUCKET}/${PEER_KEY}")
check "the peer's journalled write is readable from the shared spill" \
    "$peer_body" "peer-owned-body-do-not-touch"

head -c 262144 /dev/urandom >"${WORK}/own.bin"
for i in $(seq 1 12); do
    curl -s -o /dev/null -X PUT --data-binary "@${WORK}/own.bin" \
        "${ENDPOINT}/${BUCKET}/${PREFIX}/own${i}.bin"
done
stop PID1

left=$(find "$OWN_SPILL" -name '*.d' | wc -l | tr -d ' ')
check "only the peer's entry is left unflushed" "$left" "1"
if [[ "$left" == "1" ]] && grep -rqs 'peer-owned-body-do-not-touch' "$OWN_SPILL"; then
    ok "the peer's journalled write survived our shutdown untouched"
else
    bad "our shutdown consumed or destroyed a peer instance's journalled write"
fi

# And the objects we acknowledged really did land, read back with no cache.
start PID2 "$BIND2" SPICEIO_WRITE_BACK=0 SPICEIO_SPILL_DIR=off
curl -s -o "${WORK}/own.get" "${ENDPOINT2}/${BUCKET}/${PREFIX}/own1.bin"
if cmp -s "${WORK}/own.bin" "${WORK}/own.get"; then
    ok "our acknowledged writes reached the NAS before exit"
else
    bad "an acknowledged write did not reach the NAS before exit"
fi
# A GET that 404s on the backend must not delete a peer's journalled write.
curl -s -o /dev/null "${ENDPOINT2}/${BUCKET}/${PREFIX}/definitely-absent.bin"
for i in $(seq 1 12); do
    curl -s -o /dev/null -X DELETE "${ENDPOINT2}/${BUCKET}/${PREFIX}/own${i}.bin"
done
stop PID2
rm -rf "$OWN_SPILL"

# ── Cleanup of test objects ────────────────────────────────────────────────
start PID1 "$BIND" SPICEIO_WRITE_BACK=0 SPICEIO_SPILL_DIR=off
for key in "${PREFIX}/small.bin" "${PREFIX}/large.bin" "$range_key" "$ow_key"; do
    curl -s -o /dev/null -X DELETE "${ENDPOINT}/${BUCKET}/${key}"
done
stop PID1

# ── Stderr guard (same rule as the other live suites) ──────────────────────
if grep -q -r '\[spiceio\] error:' "$LOG_DIR" 2>/dev/null; then
    echo ""
    echo "FAIL: spiceio emitted unexpected error log lines:"
    grep -r '\[spiceio\] error:' "$LOG_DIR" | head -20
    FAIL=$((FAIL + 1))
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo " TOTAL: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════════════════════"

[[ "$FAIL" -gt 0 ]] && exit 1
exit 0
