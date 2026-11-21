#!/usr/bin/env bash
# Hermetic tests for scripts/codesign-local.sh and for the keychain-backed SMB
# password end to end: that an item stored by one signed build is readable by
# another build signed with the same identity, and by nothing else.
#
# Everything happens in throwaway keychain files under a temp directory, none
# of them on the keychain search list; the login keychain is never touched.
# Password prompts are answered through a pseudo-terminal (python3 pty), the
# way a person at a terminal would. No step can raise a keychain dialog: the
# script checks lock state with `spiceio --keychain-status` before codesign
# touches a keychain, and spiceio itself runs with keychain UI disabled.
#
# Usage: scripts/test-codesign-local.sh [path/to/spiceio]   (default target/debug/spiceio)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SPICEIO_BIN=$(cd "$(dirname "${1:-$ROOT/target/debug/spiceio}")" && pwd)/$(basename "${1:-spiceio}")
[[ -x "$SPICEIO_BIN" ]] || {
    echo "spiceio binary not found at $SPICEIO_BIN (cargo build first)" >&2
    exit 1
}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-codesign.XXXXXX")
# realpath: keychain paths are compared as strings, and $TMPDIR is a symlink.
WORK=$(cd "$WORK" && pwd -P)
cleanup() {
    for kc in "$WORK"/*.keychain-db; do
        [[ -e "$kc" ]] && security delete-keychain "$kc" 2>/dev/null || true
    done
    rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
ok() {
    PASS=$((PASS + 1))
    echo "  ok: $1"
}
bad() {
    FAIL=$((FAIL + 1))
    echo "  FAIL: $1"
    [[ -z "${2:-}" ]] || printf '%s\n' "$2" | sed 's/^/        /'
}
check() {
    local what=$1
    shift
    if "$@"; then ok "$what"; else bad "$what" "${OUT:-}"; fi
}
has() { grep -qF -- "$1" <<<"$OUT"; }
lacks() { ! grep -qF -- "$1" <<<"$OUT"; }

SIGN="$ROOT/scripts/codesign-local.sh"
KC="$WORK/signing.keychain-db"
PW=signing-keychain-test-pw
SECRET='p@ss w0rd&<amp>"'

# run_tty PASSWORD CMD...: run CMD on a pseudo-terminal, typing PASSWORD at
# every password prompt. OUT gets what the terminal showed, RC the status.
cat >"$WORK/pty.py" <<'EOF'
import os, pty, select, sys, time
password = os.environ["PTY_PASSWORD"].encode()
pid, fd = pty.fork()
if pid == 0:
    os.execvp(sys.argv[1], sys.argv[1:])
seen, pending, deadline = b"", b"", time.time() + 120
while time.time() < deadline:
    if not select.select([fd], [], [], 0.5)[0]:
        continue
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    seen += data
    pending += data
    if b"assword" in pending and pending.rstrip().endswith(b":"):
        os.write(fd, password + b"\n")
        pending = b""
_, status = os.waitpid(pid, 0)
sys.stdout.write(seen.decode(errors="replace"))
sys.exit(os.waitstatus_to_exitcode(status))
EOF
run_tty() {
    local password=$1
    shift
    set +e
    OUT=$(PTY_PASSWORD="$password" python3 -I "$WORK/pty.py" "$@" 2>&1)
    RC=$?
    set -e
}
# run CMD...: no terminal (stdin is /dev/null).
run() {
    set +e
    OUT=$("$@" </dev/null 2>&1)
    RC=$?
    set -e
}
state() { "$SPICEIO_BIN" --keychain-status "$1"; }
# cs ARGS...: codesign, quiet on success, its own error on failure (set -e
# then stops the run with a reason instead of silently).
cs() {
    local out
    if ! out=$(codesign "$@" 2>&1); then
        echo "setup failed: codesign $*:" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi
}
requirement() { codesign -d -r- "$1" 2>&1 | sed -n 's/^designated => //p'; }
cdhash() { codesign -dvvv "$1" 2>&1 | sed -n 's/^CDHash=//p'; }
mode_of() { stat -f '%Lp' "$1"; }

echo "--- first run creates the signing keychain and identity, then signs"
run_tty "$PW" env SIGNING_KEYCHAIN="$KC" sh "$SIGN" "$SPICEIO_BIN" "$WORK/a"
check "exits 0" [ "$RC" -eq 0 ]
check "asks for a new password (and to retype it)" has "retype password for new keychain"
check "creates the keychain 0600" [ "$(mode_of "$KC")" = 600 ]
check "signs with the certificate" grep -q '^identifier "ai.spice.spiceio" and certificate leaf = H"' <<<"$(requirement "$WORK/a")"
check "with the hardened runtime" grep -q 'flags=0x10000(runtime)' <<<"$(codesign -dv "$WORK/a" 2>&1)"
check "the signature verifies" codesign --verify --strict "$WORK/a"
check "says what it signed with" has "signed $WORK/a: identifier \"ai.spice.spiceio\""
check "locks the keychain when done" [ "$(state "$KC")" = locked ]
off_search_list() { ! security list-keychains -d user | grep -qF "$1"; }
check "keeps it off the keychain search list" off_search_list "$KC"
security unlock-keychain -p "$PW" "$KC"
set +e
OUT=$(security export -k "$KC" -t privKeys -f pkcs12 -P x -o "$WORK/key.p12" 2>&1)
RC=$?
set -e
check "the private key cannot be exported" [ "$RC" -ne 0 ]
HASH=$(security find-identity -p codesigning "$KC" | awk '/Matching identities/ {m=1} m && /spiceio local code signing/ {print $2; exit}')
[[ -n "$HASH" ]] || {
    echo "setup failed: no signing identity in $KC:" >&2
    security find-identity -p codesigning "$KC" >&2
    exit 1
}
security lock-keychain "$KC"
REQ_A=$(requirement "$WORK/a")

echo "--- locked, no terminal: refuses without prompting, writes nothing"
run env SIGNING_KEYCHAIN="$KC" sh "$SIGN" "$SPICEIO_BIN" "$WORK/b"
check "exits 1" [ "$RC" -eq 1 ]
check "says how to unlock it first" has "security unlock-keychain '$KC'"
check "leaves no output binary" [ ! -e "$WORK/b" ]
check "still locked" [ "$(state "$KC")" = locked ]

echo "--- locked, in a terminal: asks once, signs, locks again"
run_tty "$PW" env SIGNING_KEYCHAIN="$KC" sh "$SIGN" "$SPICEIO_BIN" "$WORK/b"
check "exits 0" [ "$RC" -eq 0 ]
check "asks for the signing keychain's password" has "password to unlock $KC"
check "the same designated requirement as before" [ "$(requirement "$WORK/b")" = "$REQ_A" ]
check "locked again" [ "$(state "$KC")" = locked ]

echo "--- unlocked beforehand, no terminal: no prompt, locked again"
security unlock-keychain -p "$PW" "$KC"
run env SIGNING_KEYCHAIN="$KC" sh "$SIGN" "$SPICEIO_BIN" "$WORK/c"
check "exits 0" [ "$RC" -eq 0 ]
check "asks for nothing" lacks "assword"
check "locked again" [ "$(state "$KC")" = locked ]

echo "--- no signing keychain and no terminal"
run env SIGNING_KEYCHAIN="$WORK/none.keychain-db" sh "$SIGN" "$SPICEIO_BIN" "$WORK/d"
check "exits 1" [ "$RC" -eq 1 ]
check "says to run it in a terminal once" has "in a terminal once"
check "creates no keychain" [ ! -e "$WORK/none.keychain-db" ]

echo "--- a signing keychain without the identity"
security create-keychain -p "$PW" "$WORK/empty.keychain-db"
run env SIGNING_KEYCHAIN="$WORK/empty.keychain-db" sh "$SIGN" "$SPICEIO_BIN" "$WORK/d"
check "exits 1" [ "$RC" -eq 1 ]
check "says how to start over" has "has no \"spiceio local code signing\" identity"
check "leaves no output binary" [ ! -e "$WORK/d" ]

echo "--- CODESIGN=adhoc"
run env CODESIGN=adhoc SIGNING_KEYCHAIN="$WORK/none.keychain-db" sh "$SIGN" "$SPICEIO_BIN" "$WORK/adhoc"
check "exits 0" [ "$RC" -eq 0 ]
check "the requirement is the cdhash" grep -q 'cdhash' <<<"$(codesign -d -r- "$WORK/adhoc" 2>&1)"
run env CODESIGN=sometimes sh "$SIGN" "$SPICEIO_BIN" "$WORK/x"
check "unknown CODESIGN: exits 1" [ "$RC" -eq 1 ]

# ── the keychain item follows the identity, not the build ────────────────
ITEMS="$WORK/items.keychain-db"
security create-keychain -p items-pw "$ITEMS"
security set-keychain-settings "$ITEMS"
smb() {
    env -i PATH=/usr/bin:/bin HOME="$WORK" \
        SPICEIO_SMB_SERVER=nas.example SPICEIO_SMB_USER=svc-spiceio \
        SPICEIO_SMB_PASS_KEYCHAIN=ai.spice.spiceio.smb SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" "$@"
}
stdin_run() { # INPUT CMD...: CMD with INPUT on stdin
    local input=$1
    shift
    set +e
    OUT=$(printf '%s' "$input" | "$@" 2>&1)
    RC=$?
    set -e
}

echo "--- the signed build stores the password"
stdin_run "$SECRET" smb "$WORK/a" --store-smb-password
check "exits 0" [ "$RC" -eq 0 ]
check "says added, for the server" has "SMB password for smb://****@nas.example: added in keychain item \"ai.spice.spiceio.smb\""
check "never prints the SMB user" lacks "svc-spiceio"
check "names the requirement that may read it" has "readable by: $REQ_A"
check "no ad-hoc warning" lacks "ad-hoc"
check "never prints the password" lacks "$SECRET"
stdin_run "$SECRET" smb "$WORK/a" --store-smb-password
check "the same bytes again: unchanged (so the first store was byte for byte)" has ": unchanged in keychain item"
stdin_run "$SECRET"$'\n' smb "$WORK/a" --store-smb-password
check "one trailing newline on stdin is not part of the password" has ": unchanged in keychain item"

echo "--- a different build signed with the same identity reads it"
security unlock-keychain -p "$PW" "$KC"
cp "$WORK/a" "$WORK/rebuilt"
# A rebuild changes the cdhash; so does a different CodeDirectory flag, which
# is how this stands in for one without recompiling. The keychain checks the
# designated requirement, which names the identity, not the cdhash.
cs -f -s "$HASH" --keychain "$KC" -i ai.spice.spiceio -o runtime,kill --timestamp=none "$WORK/rebuilt"
security lock-keychain "$KC"
check "its cdhash differs" [ "$(cdhash "$WORK/rebuilt")" != "$(cdhash "$WORK/a")" ]
check "its requirement is the same" [ "$(requirement "$WORK/rebuilt")" = "$REQ_A" ]
run smb "$WORK/rebuilt" --check-smb-password
check "exits 0" [ "$RC" -eq 0 ]
check "and says where the password came from" has "SMB password: keychain item \"ai.spice.spiceio.smb\" for smb://****@nas.example (keychain $ITEMS)"
check "without the SMB user" lacks "svc-spiceio"

echo "--- an ad-hoc build is refused, and cannot clobber it"
cp "$WORK/a" "$WORK/unsigned"
cs -f -s - -i ai.spice.spiceio "$WORK/unsigned"
run smb "$WORK/unsigned" --check-smb-password
check "exits 1" [ "$RC" -eq 1 ]
check "says its signature is not on the access list" has "is not on the item's access list"
check "names the command that deletes the item" has "security delete-generic-password -s 'ai.spice.spiceio.smb' -a 'smb://<user>@nas.example' '$ITEMS'"
check "with a placeholder, not the SMB user" lacks "svc-spiceio"
stdin_run "attacker-chosen" smb "$WORK/unsigned" --store-smb-password
check "store from it exits 1" [ "$RC" -eq 1 ]
check "warns that it is ad-hoc" has "warning: this spiceio binary is ad-hoc signed"
check "and leaves the item alone" has "left alone"
stdin_run "$SECRET" smb "$WORK/a" --store-smb-password
check "the stored password is still the original" has ": unchanged in keychain item"

echo "--- a build signed with another identity is refused"
KC2="$WORK/other.keychain-db"
run_tty "$PW" env SIGNING_KEYCHAIN="$KC2" sh "$SIGN" "$SPICEIO_BIN" "$WORK/other"
check "the other identity signs" [ "$RC" -eq 0 ]
check "with a different requirement" [ "$(requirement "$WORK/other")" != "$REQ_A" ]
run smb "$WORK/other" --check-smb-password
check "exits 1" [ "$RC" -eq 1 ]
check "not on the access list" has "is not on the item's access list"

echo "--- the item is bound to the server"
run env -i PATH=/usr/bin:/bin HOME="$WORK" SPICEIO_SMB_SERVER=attacker.example SPICEIO_SMB_USER=svc-spiceio \
    SPICEIO_SMB_PASS_KEYCHAIN=ai.spice.spiceio.smb SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" \
    "$WORK/a" --check-smb-password
check "a changed server finds no item" [ "$RC" -eq 1 ]
check "and says so" has "no keychain item \"ai.spice.spiceio.smb\" for smb://****@attacker.example"

echo "--- interactive store"
run_tty "$SECRET" env -i PATH=/usr/bin:/bin HOME="$WORK" SPICEIO_SMB_SERVER=nas.example SPICEIO_SMB_USER=svc-spiceio \
    SPICEIO_SMB_PASS_KEYCHAIN=ai.spice.spiceio.smb SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" \
    "$WORK/a" --store-smb-password
check "exits 0" [ "$RC" -eq 0 ]
check "asks for the password for that server" has "SMB password for smb://****@nas.example:"
check "asks twice" has "Retype the password:"
check "does not echo it" lacks "$SECRET"
check "same password: unchanged" has ": unchanged in keychain item"
run_tty "a-new-password" env -i PATH=/usr/bin:/bin HOME="$WORK" SPICEIO_SMB_SERVER=nas.example SPICEIO_SMB_USER=svc-spiceio \
    SPICEIO_SMB_PASS_KEYCHAIN=ai.spice.spiceio.smb SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" \
    "$WORK/a" --store-smb-password
check "a changed password from the terminal: updated" has ": updated in keychain item"
stdin_run "$SECRET" smb "$WORK/a" --store-smb-password
check "and back again from stdin: updated" has ": updated in keychain item"

echo "--- flags instead of the environment"
flags() { env -i PATH=/usr/bin:/bin HOME="$WORK" SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" "$@"; }
stdin_run "$SECRET" flags "$WORK/a" --store-smb-password --server nas.example --user svc-spiceio --service ai.spice.spiceio.smb
check "--server/--user/--service find the same item" has ": unchanged in keychain item"
run flags "$WORK/a" --check-smb-password --server=nas.example --user=svc-spiceio --service=ai.spice.spiceio.smb
check "--check-smb-password takes them too" [ "$RC" -eq 0 ]
run smb "$WORK/a" --check-smb-password --server attacker.example
check "a flag overrides its variable" has "for smb://****@attacker.example"
stdin_run "x" flags "$WORK/a" --store-smb-password --server nas.example --user svc-spiceio --password "$SECRET"
check "--password: exits 1" [ "$RC" -eq 1 ]
check "and says why" has "never taken from the command line"
check "without echoing it" lacks "$SECRET"
run flags "$WORK/a" --check-smb-password --sever nas.example
check "an unknown flag: exits 1" [ "$RC" -eq 1 ]
check "and names it" has "unknown argument \"--sever\""

echo "--- refusals"
stdin_run "x" smb SPICEIO_SMB_PASS=inline "$WORK/a" --store-smb-password
check "store with SPICEIO_SMB_PASS set: exits 1" [ "$RC" -eq 1 ]
check "and says it never reads the environment" has "SPICEIO_SMB_PASS is set"
run smb SPICEIO_SMB_PASS=inline "$WORK/a" --check-smb-password
check "both sources configured: exits 1" [ "$RC" -eq 1 ]
check "and says not both" has "not both"
stdin_run "" smb "$WORK/a" --store-smb-password
check "empty password: exits 1" [ "$RC" -eq 1 ]
security lock-keychain "$ITEMS"
run smb "$WORK/a" --check-smb-password
check "locked item keychain: exits 1" [ "$RC" -eq 1 ]
check "and says it is locked" has "is locked, and spiceio never prompts"
security unlock-keychain -p items-pw "$ITEMS"
run env -i PATH=/usr/bin:/bin SPICEIO_SMB_PASS=inline "$WORK/a" --check-smb-password
check "an inline password still works" [ "$RC" -eq 0 ]
check "and is reported as such" has "SMB password: SPICEIO_SMB_PASS (environment)"

echo ""
echo "codesign-local: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
