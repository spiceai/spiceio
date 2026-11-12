#!/usr/bin/env bash
set -euo pipefail

# ── S3 authentication + aws-chunked live test ─────────────────────────────
#
# Runs three spiceio instances in turn against the real share, each in one
# SPICEIO_S3_AUTH mode:
#
#   1. enforce — every client signs with its own SigV4 implementation (curl
#      --aws-sigv4, aws-cli, mc when installed, and sccache), and every
#      rejection path is exercised: unsigned, wrong secret, unknown key,
#      tampered presigned URL, a body that does not match its signed digest.
#   2. log     — the same rejected requests are served, and logged.
#   3. off     — write-back, spill and object cache all off, so every GET
#      reads the NAS. Reads back what the enforce instance wrote (aws-chunked
#      and signed-chunk uploads must have landed *decoded*, not with their
#      framing), and checks that unsigned aws-chunked uploads decode too.
#
# Unit tests pin canonicalization against captured requests; this is the
# check that the same clients, live, interoperate end to end.
#
# Usage: SPICEIO_SMB_USER=u SPICEIO_SMB_PASS=p ./scripts/test-auth.sh

SMB_SERVER="${SPICEIO_SMB_SERVER:-192.168.3.148}"
SMB_SHARE="${SPICEIO_SMB_SHARE:-ai_platform_dev}"
SMB_PORT="${SPICEIO_SMB_PORT:-445}"
SMB_DOMAIN="${SPICEIO_SMB_DOMAIN:-}"
REGION="${SPICEIO_REGION:-us-east-1}"
BUCKET="${SPICEIO_BUCKET:-auth}"
BIND="${SPICEIO_BIND:-127.0.0.1:18339}"
SMB_CONNECTIONS="${SPICEIO_SMB_CONNECTIONS:-8}"

: "${SPICEIO_SMB_USER:?SPICEIO_SMB_USER is required}"
: "${SPICEIO_SMB_PASS:?SPICEIO_SMB_PASS is required}"

SPICEIO_BIN="./target/debug/spiceio"
ENDPOINT="http://${BIND}"
TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
PREFIX="auth-$$-${TOKEN}"
WORK=$(mktemp -d /tmp/spiceio-auth.XXXXXX)
SPICEIO_STDERR="${WORK}/spiceio.log"
: > "$SPICEIO_STDERR"
PASS=0
FAIL=0

# Two keys in a credentials file (a rotation in progress), generated per run.
KEY_A="spiceio-test-a-${TOKEN}"
KEY_B="spiceio-test-b-${TOKEN}"
SECRET_A=$(python3 -c 'import secrets; print(secrets.token_urlsafe(30))')
SECRET_B=$(python3 -c 'import secrets; print(secrets.token_urlsafe(30))')
KEYS_FILE="${WORK}/keys"
printf '# test keys\n%s %s\n%s %s\n' "$KEY_A" "$SECRET_A" "$KEY_B" "$SECRET_B" > "$KEYS_FILE"
chmod 600 "$KEYS_FILE"

# Hermetic aws-cli: no profile, config or session token from the caller.
aws_as() {
    local key="$1" secret="$2"
    shift 2
    env -u AWS_PROFILE -u AWS_SESSION_TOKEN -u AWS_DEFAULT_PROFILE \
        AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        AWS_ACCESS_KEY_ID="$key" AWS_SECRET_ACCESS_KEY="$secret" \
        aws --endpoint-url "$ENDPOINT" --region "$REGION" "$@"
}
aws_signed() { aws_as "$KEY_A" "$SECRET_A" "$@"; }
aws_anon() {
    env -u AWS_PROFILE AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        aws --endpoint-url "$ENDPOINT" --region "$REGION" --no-sign-request "$@"
}
# curl's own SigV4 signer.
scurl() {
    curl -sS --max-time 60 --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:${SECRET_A}" "$@"
}
code_of() { curl -sS --max-time 60 -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

SPICEIO_PID=""
SCCACHE_STARTED=0
cleanup() {
    echo ""
    echo "[auth] cleaning up..."
    if [[ "$SCCACHE_STARTED" -eq 1 ]]; then
        # Through the same wrapper that started it: a bare `sccache` would
        # stop the caller's daemon on the default port and leave ours running.
        sccache_env sccache --stop-server >/dev/null 2>&1 || true
    fi
    if [[ -n "$SPICEIO_PID" ]]; then
        kill "$SPICEIO_PID" 2>/dev/null || true
        wait "$SPICEIO_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

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

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (missing '$needle' in: ${haystack:0:400})"
        FAIL=$((FAIL + 1))
    fi
}

assert_log() {
    local label="$1" pattern="$2" since="$3"
    sleep 0.3 # let the async logger flush
    if tail -c +"$((since + 1))" "$SPICEIO_STDERR" | grep -q -- "$pattern"; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (no '$pattern' in spiceio log)"
        FAIL=$((FAIL + 1))
    fi
}

log_offset() { wc -c < "$SPICEIO_STDERR" | tr -d ' '; }

same_file() { cmp -s "$1" "$2"; }

# start_spiceio [ENV=val ...] — waits until the SMB pool is up (the not-ready
# 503 is answered before authentication, so any other status means ready).
start_spiceio() {
    local stale
    stale=$(lsof -i ":${BIND##*:}" -sTCP:LISTEN -t 2>/dev/null || true)
    if [[ -n "$stale" ]]; then
        echo "[auth] FAIL: ${BIND} already in use (pid ${stale}); not killing an unverified process"
        exit 1
    fi
    env \
        -u SPICEIO_S3_AUTH -u SPICEIO_S3_ACCESS_KEY_ID \
        -u SPICEIO_S3_SECRET_ACCESS_KEY -u SPICEIO_S3_CREDENTIALS_FILE \
        -u SPICEIO_IMMUTABLE_OBJECTS -u SPICEIO_EXISTENCE_INDEX \
        SPICEIO_BIND="$BIND" \
        SPICEIO_SMB_SERVER="$SMB_SERVER" \
        SPICEIO_SMB_PORT="$SMB_PORT" \
        SPICEIO_SMB_USER="$SPICEIO_SMB_USER" \
        SPICEIO_SMB_PASS="$SPICEIO_SMB_PASS" \
        SPICEIO_SMB_DOMAIN="$SMB_DOMAIN" \
        SPICEIO_SMB_SHARE="$SMB_SHARE" \
        SPICEIO_SMB_CONNECTIONS="$SMB_CONNECTIONS" \
        SPICEIO_BUCKET="$BUCKET" \
        SPICEIO_REGION="$REGION" \
        SPICEIO_SPILL_DIR="${WORK}/spill" \
        SPICEIO_LOG_FILE="${SPICEIO_LOG_FILE:-}" \
        "$@" \
        "$SPICEIO_BIN" >> "$SPICEIO_STDERR" 2>&1 &
    SPICEIO_PID=$!
    local i code
    for i in $(seq 1 120); do
        code=$(code_of "${ENDPOINT}/")
        if [[ "$code" == "200" || "$code" == "403" ]]; then
            echo "[auth] spiceio ready (pid $SPICEIO_PID, unsigned / → $code)"
            return 0
        fi
        if ! kill -0 "$SPICEIO_PID" 2>/dev/null; then
            echo "[auth] spiceio exited unexpectedly:"
            tail -20 "$SPICEIO_STDERR"
            exit 1
        fi
        sleep 0.5
    done
    echo "[auth] spiceio not ready after 60s"
    exit 1
}

# Graceful stop: drains write-back so the next instance reads it from the NAS.
stop_spiceio() {
    [[ -z "$SPICEIO_PID" ]] && return 0
    kill -TERM "$SPICEIO_PID" 2>/dev/null || true
    wait "$SPICEIO_PID" 2>/dev/null || true
    SPICEIO_PID=""
}

# Source files.
printf 'small object\n' > "${WORK}/small.txt"
head -c 200000 /dev/urandom > "${WORK}/200k.bin"
head -c 10485760 /dev/urandom > "${WORK}/10m.bin"

if [[ ! -x "$SPICEIO_BIN" ]]; then
    echo "[auth] building spiceio..."
    cargo build --locked --bin spiceio
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "======================================="
echo "[auth] 1. SPICEIO_S3_AUTH=enforce (credentials file, two keys)"
echo "======================================="
start_spiceio SPICEIO_S3_CREDENTIALS_FILE="$KEYS_FILE"
assert_log "startup logs enforce mode and both key ids" "S3 auth: enforce (SigV4; access keys: ${KEY_A}, ${KEY_B})" 0
OFFSET=$(log_offset)

echo "--- rejections"
assert_eq "unsigned ListBuckets → 403" "403" "$(code_of "${ENDPOINT}/")"
BODY=$(curl -sS "${ENDPOINT}/${BUCKET}/${PREFIX}/small.txt" || true)
assert_contains "unsigned GetObject → AccessDenied" "<Code>AccessDenied</Code>" "$BODY"
BODY=$(curl -sS --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:wrong-secret-wrong-secret" "${ENDPOINT}/" || true)
assert_contains "wrong secret → SignatureDoesNotMatch" "<Code>SignatureDoesNotMatch</Code>" "$BODY"
assert_contains "mismatch response carries the canonical request" "<CanonicalRequest>GET" "$BODY"
BODY=$(curl -sS --aws-sigv4 "aws:amz:${REGION}:s3" --user "NOSUCHKEY:wrong-secret-wrong-secret" "${ENDPOINT}/" || true)
assert_contains "unknown key → InvalidAccessKeyId" "<Code>InvalidAccessKeyId</Code>" "$BODY"
assert_eq "CORS preflight needs no signature" "200" \
    "$(code_of -X OPTIONS -H 'Origin: http://x' -H 'Access-Control-Request-Method: GET' "${ENDPOINT}/${BUCKET}/k")"

echo "--- curl --aws-sigv4"
assert_eq "signed ListBuckets → 200" "200" "$(code_of --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:${SECRET_A}" "${ENDPOINT}/")"
assert_eq "second key from the file also works" "200" \
    "$(code_of --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_B}:${SECRET_B}" "${ENDPOINT}/")"
assert_ok "PUT, signed payload digest" scurl -f -X PUT --data-binary "@${WORK}/small.txt" "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-digest.txt"
scurl -f -o "${WORK}/curl-digest.out" "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-digest.txt" || true
assert_ok "GET returns the signed body" same_file "${WORK}/small.txt" "${WORK}/curl-digest.out"
assert_ok "PUT, UNSIGNED-PAYLOAD (-T)" scurl -f -T "${WORK}/200k.bin" "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-unsigned.bin"
scurl -f -o "${WORK}/curl-unsigned.out" "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-unsigned.bin" || true
assert_ok "GET returns the unsigned-payload body" same_file "${WORK}/200k.bin" "${WORK}/curl-unsigned.out"
# A valid signature over a digest the body does not match.
OTHER_DIGEST=$(printf 'something else' | shasum -a 256 | cut -d' ' -f1)
BODY=$(scurl -X PUT -H "x-amz-content-sha256: ${OTHER_DIGEST}" --data-binary "@${WORK}/small.txt" \
    "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-forged.txt" || true)
assert_contains "body that mismatches its signed digest → XAmzContentSHA256Mismatch" \
    "<Code>XAmzContentSHA256Mismatch</Code>" "$BODY"
assert_eq "... and was never stored" "404" \
    "$(code_of --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:${SECRET_A}" -I "${ENDPOINT}/${BUCKET}/${PREFIX}/curl-forged.txt")"

echo "--- aws-cli ($(aws --version 2>&1 | cut -d' ' -f1))"
ODD_KEY="${PREFIX}/dir/a b+c ü.txt"
assert_ok "s3api put-object (signed digest, encoded key)" \
    aws_signed s3api put-object --bucket "$BUCKET" --key "$ODD_KEY" --body "${WORK}/small.txt"
aws_signed s3api get-object --bucket "$BUCKET" --key "$ODD_KEY" "${WORK}/odd.out" >/dev/null 2>&1 || true
assert_ok "s3api get-object round trip" same_file "${WORK}/small.txt" "${WORK}/odd.out"
assert_ok "s3 cp small (aws-chunked on aws-cli ≥ 2.23)" aws_signed s3 cp --quiet "${WORK}/small.txt" "s3://${BUCKET}/${PREFIX}/cli-small.txt"
aws_signed s3 cp --quiet "s3://${BUCKET}/${PREFIX}/cli-small.txt" "${WORK}/cli-small.out" || true
assert_ok "s3 cp small round trip" same_file "${WORK}/small.txt" "${WORK}/cli-small.out"
assert_ok "s3 cp 10 MiB (multipart)" aws_signed s3 cp --quiet "${WORK}/10m.bin" "s3://${BUCKET}/${PREFIX}/cli-10m.bin"
aws_signed s3 cp --quiet "s3://${BUCKET}/${PREFIX}/cli-10m.bin" "${WORK}/cli-10m.out" || true
assert_ok "s3 cp 10 MiB round trip" same_file "${WORK}/10m.bin" "${WORK}/cli-10m.out"
LISTING=$(aws_signed s3 ls "s3://${BUCKET}/${PREFIX}/dir/" 2>&1 || true)
# Signed ListObjectsV2 with prefix, delimiter and encoding-type=url. Checked
# on the part of the name a listing renders faithfully: spiceio echoes
# EncodingType=url without URL-encoding keys, so aws-cli shows a '+' in a key
# as a space (a listing bug independent of authentication).
assert_contains "s3 ls of an encoded prefix" "c ü.txt" "$LISTING"
assert_ok "s3api copy-object (signed x-amz-copy-source)" \
    aws_signed s3api copy-object --bucket "$BUCKET" --key "${PREFIX}/copy.txt" \
    --copy-source "${BUCKET}/${PREFIX}/cli-small.txt"
aws_signed s3 cp --quiet "s3://${BUCKET}/${PREFIX}/copy.txt" "${WORK}/copy.out" || true
assert_ok "copy round trip" same_file "${WORK}/small.txt" "${WORK}/copy.out"
assert_ok "s3api delete-objects" aws_signed s3api delete-objects --bucket "$BUCKET" \
    --delete "{\"Objects\":[{\"Key\":\"${PREFIX}/copy.txt\"}]}"
assert_eq "deleted object is gone" "404" \
    "$(code_of --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:${SECRET_A}" -I "${ENDPOINT}/${BUCKET}/${PREFIX}/copy.txt")"
BODY=$(aws_as "$KEY_A" "wrong-secret-wrong-secret" s3 ls "s3://${BUCKET}/${PREFIX}/" 2>&1 || true)
assert_contains "aws-cli with the wrong secret is refused" "SignatureDoesNotMatch" "$BODY"

echo "--- presigned URL"
URL=$(aws_signed s3 presign "s3://${BUCKET}/${PREFIX}/cli-small.txt" --expires-in 300)
curl -sS -f -o "${WORK}/presigned.out" "$URL" || true
assert_ok "presigned GET round trip" same_file "${WORK}/small.txt" "${WORK}/presigned.out"
assert_eq "presigned URL with a stretched expiry → 403" "403" "$(code_of "${URL/X-Amz-Expires=300/X-Amz-Expires=3000}")"
assert_eq "presigned URL for another key → 403" "403" "$(code_of "${URL/cli-small.txt/cli-10m.bin}")"

echo "--- mc (minio-go: signed aws-chunked)"
if command -v mc >/dev/null 2>&1; then
    export MC_CONFIG_DIR="${WORK}/mc"
    mc alias set authtest "$ENDPOINT" "$KEY_A" "$SECRET_A" --api s3v4 --path on >/dev/null
    mc alias set authbad "$ENDPOINT" "$KEY_A" "wrong-secret-wrong-secret" --api s3v4 --path on >/dev/null
    assert_ok "mc cp small" mc cp --quiet "${WORK}/small.txt" "authtest/${BUCKET}/${PREFIX}/mc-small.txt"
    assert_ok "mc cp 200 KB (several signed chunks)" mc cp --quiet "${WORK}/200k.bin" "authtest/${BUCKET}/${PREFIX}/mc-200k.bin"
    mc cat "authtest/${BUCKET}/${PREFIX}/mc-200k.bin" > "${WORK}/mc-200k.out" 2>/dev/null || true
    assert_ok "mc round trip" same_file "${WORK}/200k.bin" "${WORK}/mc-200k.out"
    if mc cp --quiet "${WORK}/small.txt" "authbad/${BUCKET}/${PREFIX}/mc-bad.txt" >/dev/null 2>&1; then
        echo "  FAIL: mc with the wrong secret was accepted"
        FAIL=$((FAIL + 1))
    else
        echo "  PASS: mc with the wrong secret is refused"
        PASS=$((PASS + 1))
    fi
    MC_RAN=1
else
    echo "  SKIP: mc not installed (signed aws-chunked is still covered by unit fixtures)"
    MC_RAN=0
fi

echo "--- sccache ($(sccache --version 2>/dev/null || echo 'not installed'))"
if command -v sccache >/dev/null 2>&1; then
    SCCACHE_SERVER_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
    CRATE="${WORK}/crate"
    mkdir -p "${CRATE}/src"
    printf '[package]\nname = "spiceio_auth_probe"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\npath = "src/lib.rs"\n' > "${CRATE}/Cargo.toml"
    printf 'pub fn token() -> &%sstatic str { "%s" }\n' "'" "$TOKEN" > "${CRATE}/src/lib.rs"
    # Everything sccache reads goes through `env`, so the caller's sccache
    # daemon, backend and credentials are untouched.
    sccache_env() {
        env -u SCCACHE_DIR -u SCCACHE_GCS_BUCKET -u SCCACHE_AZURE_CONNECTION_STRING \
            -u SCCACHE_REDIS -u SCCACHE_MEMCACHED -u SCCACHE_WEBDAV_ENDPOINT \
            -u SCCACHE_S3_NO_CREDENTIALS -u AWS_PROFILE -u AWS_SESSION_TOKEN \
            AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
            SCCACHE_SERVER_PORT="$SCCACHE_SERVER_PORT" \
            SCCACHE_BUCKET="$BUCKET" SCCACHE_ENDPOINT="$ENDPOINT" SCCACHE_REGION="$REGION" \
            SCCACHE_S3_USE_SSL=false SCCACHE_S3_KEY_PREFIX="${PREFIX}/sccache" \
            AWS_ACCESS_KEY_ID="$KEY_A" AWS_SECRET_ACCESS_KEY="$SECRET_A" \
            RUSTC_WRAPPER=sccache CARGO_INCREMENTAL=0 "$@"
    }
    sccache_env sccache --start-server >/dev/null
    SCCACHE_STARTED=1
    sccache_env cargo build --quiet --manifest-path "${CRATE}/Cargo.toml" --target-dir "${WORK}/crate-target"
    sccache_env sccache --zero-stats >/dev/null
    rm -rf "${WORK}/crate-target"
    sccache_env cargo build --quiet --manifest-path "${CRATE}/Cargo.toml" --target-dir "${WORK}/crate-target"
    STATS=$(sccache_env sccache --show-stats 2>&1)
    sccache_env sccache --stop-server >/dev/null 2>&1 || true
    SCCACHE_STARTED=0
    HITS=$(echo "$STATS" | grep -m1 "^Cache hits" | awk '{print $NF}')
    ERRS=$(( $(echo "$STATS" | grep -m1 "Cache write errors" | awk '{print $NF}') \
        + $(echo "$STATS" | grep -m1 "Cache read errors" | awk '{print $NF}') ))
    assert_eq "sccache warm build hits the signed cache" "1" "$([[ "${HITS:-0}" -gt 0 ]] && echo 1 || echo 0)"
    assert_eq "sccache read/write errors" "0" "$ERRS"
else
    echo "  SKIP: sccache not installed"
fi

# Rejection logging is rate-limited to a line per second, so this is checked
# once over the whole section rather than right after a burst of rejections.
assert_log "rejections are logged" "auth: rejected" "$OFFSET"
stop_spiceio

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "======================================="
echo "[auth] 2. SPICEIO_S3_AUTH=log"
echo "======================================="
OFFSET=$(log_offset)
start_spiceio SPICEIO_S3_CREDENTIALS_FILE="$KEYS_FILE" SPICEIO_S3_AUTH=log
assert_eq "unsigned ListBuckets is served" "200" "$(code_of "${ENDPOINT}/")"
assert_eq "wrong-secret request is served" "200" \
    "$(code_of --aws-sigv4 "aws:amz:${REGION}:s3" --user "${KEY_A}:wrong-secret-wrong-secret" "${ENDPOINT}/")"
assert_log "and both are reported" "would reject (log mode)" "$OFFSET"
stop_spiceio

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "======================================="
echo "[auth] 3. SPICEIO_S3_AUTH off, every cache off (reads hit the NAS)"
echo "======================================="
OFFSET=$(log_offset)
start_spiceio SPICEIO_WRITE_BACK=0 SPICEIO_SPILL_DIR=off SPICEIO_OBJECT_CACHE_BYTES=1
assert_log "startup logs auth off" "S3 auth: off" "$OFFSET"
echo "--- what the enforce instance stored is the decoded payload"
for pair in "cli-small.txt:small.txt" "cli-10m.bin:10m.bin" "curl-unsigned.bin:200k.bin"; do
    key="${pair%%:*}" src="${pair##*:}"
    curl -sS -f -o "${WORK}/nas-${key}" "${ENDPOINT}/${BUCKET}/${PREFIX}/${key}" || true
    assert_ok "NAS copy of ${key} matches its source" same_file "${WORK}/${src}" "${WORK}/nas-${key}"
done
if [[ "$MC_RAN" -eq 1 ]]; then
    curl -sS -f -o "${WORK}/nas-mc" "${ENDPOINT}/${BUCKET}/${PREFIX}/mc-200k.bin" || true
    assert_ok "NAS copy of the mc signed-chunk upload matches" same_file "${WORK}/200k.bin" "${WORK}/nas-mc"
fi

echo "--- unsigned aws-chunked decodes in off mode (regression: framing was stored)"
printf 'B\r\nhello world\r\n0\r\nx-amz-checksum-crc32:DUoRhQ==\r\n\r\n' > "${WORK}/chunked.body"
assert_eq "raw aws-chunked PUT" "200" "$(code_of -X PUT \
    -H 'Content-Encoding: aws-chunked' \
    -H 'x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER' \
    -H 'x-amz-decoded-content-length: 11' \
    -H 'x-amz-trailer: x-amz-checksum-crc32' \
    --data-binary "@${WORK}/chunked.body" "${ENDPOINT}/${BUCKET}/${PREFIX}/raw-chunked.txt")"
assert_eq "stored body is the decoded payload" "hello world" \
    "$(curl -sS "${ENDPOINT}/${BUCKET}/${PREFIX}/raw-chunked.txt" || true)"
assert_eq "aws-chunked without x-amz-decoded-content-length → 411" "411" "$(code_of -X PUT \
    -H 'Content-Encoding: aws-chunked' --data-binary "@${WORK}/chunked.body" \
    "${ENDPOINT}/${BUCKET}/${PREFIX}/raw-chunked-2.txt")"
assert_ok "aws s3 cp --no-sign-request" aws_anon s3 cp --quiet "${WORK}/200k.bin" "s3://${BUCKET}/${PREFIX}/anon.bin"
curl -sS -f -o "${WORK}/anon.out" "${ENDPOINT}/${BUCKET}/${PREFIX}/anon.bin" || true
assert_ok "anonymous aws-cli upload round trip (from the NAS)" same_file "${WORK}/200k.bin" "${WORK}/anon.out"

aws_anon s3 rm --recursive --quiet "s3://${BUCKET}/${PREFIX}/" >/dev/null 2>&1 || true
stop_spiceio

# ── Stderr guard ────────────────────────────────────────────────────────────
sleep 0.2
if grep -q '\[spiceio\] error:' "$SPICEIO_STDERR"; then
    echo "  FAIL: spiceio logged unexpected errors:"
    grep '\[spiceio\] error:' "$SPICEIO_STDERR" | head -20
    FAIL=$((FAIL + 1))
fi

echo ""
echo "======================================="
echo "[auth] $PASS passed, $FAIL failed"
echo "======================================="
if [[ "$FAIL" -gt 0 ]]; then
    echo "[auth] last 40 lines of spiceio output:"
    tail -40 "$SPICEIO_STDERR"
    exit 1
fi
