#!/usr/bin/env bash
# Hermetic tests for `make install`'s launchd half (scripts/agent-install.sh)
# and the sccache-spiceio wrapper. No launchd agent is touched: `launchctl`
# and `lsof` are stubs on PATH that record what they were asked to do. A small
# local HTTP server stands in for the agent when the post-restart check needs
# answers. plutil, curl, openssl, codesign, `spiceio --check-auth` and the
# keychain are the real ones, so the plist edits, the auth validation and the
# move of the SMB password into the keychain are exactly what an install does.
# The keychains are throwaway files (every test plist names one in
# SPICEIO_SMB_PASS_KEYCHAIN_PATH); the login keychain is never touched.
# Real SigV4 verification against a running agent is test-auth.sh's job.
#
# Usage: scripts/test-agent-install.sh [path/to/spiceio]   (default target/debug/spiceio)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SPICEIO_BIN=$(cd "$(dirname "${1:-$ROOT/target/debug/spiceio}")" && pwd)/$(basename "${1:-spiceio}")
[[ -x "$SPICEIO_BIN" ]] || {
    echo "spiceio binary not found at $SPICEIO_BIN (cargo build first)" >&2
    exit 1
}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-agent-install.XXXXXX")
# Resolved: `security list-keychains` prints /private/var/…, not /var/….
WORK=$(cd "$WORK" && pwd -P)
SERVER_PID=""
SEARCH_LIST_BEFORE=$(security list-keychains -d user)
cleanup() {
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
    for kc in "$WORK"/*.keychain-db; do
        [[ -e "$kc" ]] || continue
        security delete-keychain "$kc" 2>/dev/null || true
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
check() { # description, then a command that must succeed
    local what=$1
    shift
    if "$@"; then ok "$what"; else bad "$what" "${OUT:-}"; fi
}
has() { grep -qF -- "$1" <<<"$OUT"; }
lacks() { ! grep -qF -- "$1" <<<"$OUT"; }

LABEL=ai.spice.spiceio-test
mkdir -p "$WORK/bin" "$WORK/bindir" "$WORK/adhocbin"
install -m 0755 "$ROOT/scripts/sccache-spiceio" "$WORK/bindir/sccache-spiceio"
install -m 0755 "$ROOT/scripts/sccache-spiceio" "$WORK/adhocbin/sccache-spiceio"

# The installed spiceio is signed the way `make install` signs it (a
# self-signed identity in its own keychain), so keychain items it stores pin
# that identity rather than one build.
SIGNING_KC="$WORK/signing.keychain-db"
# setup WHAT CMD...: run a setup step, quiet on success; on failure say which
# step and show its output, then stop (set -e) with that reason.
setup() {
    local what=$1 out
    shift
    if ! out=$("$@" 2>&1); then
        echo "setup failed: $what ($*):" >&2
        printf '%s\n' "$out" >&2
        return 1
    fi
}
# The identity is made by scripts/codesign-local.sh itself, on a pseudo-
# terminal that types the password at its prompts: the path `make install`
# takes. Not by hand with `security set-key-partition-list -k`: that form
# raised a GUI keychain dialog (securityd: "displaying keychain prompt for
# /usr/bin/security") on every run, which a test must never do.
PTY="$ROOT/scripts/pty-answer.py"
setup "create the signing identity (scripts/codesign-local.sh)" env PTY_PASSWORD=signing-pw \
    SIGNING_KEYCHAIN="$SIGNING_KC" python3 -I "$PTY" sh "$ROOT/scripts/codesign-local.sh" \
    "$SPICEIO_BIN" "$WORK/bindir/spiceio"
# codesign-local.sh locks it when done; the variants below sign directly.
setup "unlock the signing keychain" security unlock-keychain -p signing-pw "$SIGNING_KC"
SIGNING_HASH=$(security find-identity -p codesigning "$SIGNING_KC" | awk '/Matching identities/ {m=1} m && /spiceio local/ {print $2; exit}')
[[ -n "$SIGNING_HASH" ]] || {
    echo "setup failed: no signing identity in $SIGNING_KC:" >&2
    security find-identity -p codesigning "$SIGNING_KC" >&2
    exit 1
}
source "$ROOT/scripts/test-keychain-lib.sh"
# sign DST [extra -o flags]: a copy of the binary under test, signed with it.
sign() {
    cp "$SPICEIO_BIN" "$1"
    signing "$SIGNING_KC" setup "sign $1" codesign -f -s "$SIGNING_HASH" --keychain "$SIGNING_KC" \
        -i ai.spice.spiceio -o "runtime${2:+,$2}" --timestamp=none "$1" || {
        signing_diagnostics "$SIGNING_KC"
        return 1
    }
}
cp "$SPICEIO_BIN" "$WORK/adhocbin/spiceio"
setup "ad-hoc sign" codesign -f -s - -i ai.spice.spiceio "$WORK/adhocbin/spiceio"

# Where every test agent keeps its SMB password.
ITEMS="$WORK/items.keychain-db"
setup "create the item keychain" security create-keychain -p items-pw "$ITEMS"
setup "configure the item keychain" security set-keychain-settings "$ITEMS"

# ── stubs ────────────────────────────────────────────────────────────────
# launchctl: one job whose state lives in $LD_STATE. `bootstrap` snapshots
# the plist's EnvironmentVariables as the loaded environment, as launchd
# does, so a later plist edit is visible as a stale job.
cat >"$WORK/bin/launchctl" <<'EOF'
#!/bin/sh
s="$LD_STATE"
echo "$*" >>"$s/calls"
case "$1" in
print)
    [ -f "$s/loaded" ] || { echo "Could not find service" >&2; exit 113; }
    printf '%s = {\n\tpath = %s\n\tstate = running\n' "$2" "$(cat "$s/path")"
    printf '\tenvironment = {\n'
    cat "$s/env"
    printf '\t\tXPC_SERVICE_NAME => stub\n\t}\n\texit timeout = 5\n\tpid = 4242\n}\n'
    ;;
bootstrap)
    : >"$s/env"
    for k in $(plutil -extract EnvironmentVariables raw -o - "$3" 2>/dev/null); do
        printf '\t\t%s => %s\n' "$k" "$(plutil -extract "EnvironmentVariables.$k" raw -o - "$3")" >>"$s/env"
    done
    printf '%s' "$3" >"$s/path"
    touch "$s/loaded"
    ;;
bootout) rm -f "$s/loaded" ;;
kickstart) ;;
*) echo "stub launchctl: unexpected $*" >&2; exit 1 ;;
esac
EOF
# lsof: the agent listens wherever $LSOF_ADDR says (nowhere when empty).
cat >"$WORK/bin/lsof" <<'EOF'
#!/bin/sh
[ -z "${LSOF_ADDR:-}" ] || echo "n$LSOF_ADDR"
EOF
chmod +x "$WORK/bin/launchctl" "$WORK/bin/lsof"

# A stand-in agent: answers unsigned requests with $UNSIGNED, requests signed
# with access key $KEY with $SIGNED, other signatures with 403, and the first
# $BUSY requests with 503 (SMB still connecting).
cat >"$WORK/server.py" <<'EOF'
import http.server, os, sys
cfg = dict(a.split("=", 1) for a in sys.argv[2:])
busy = [int(cfg.get("BUSY", "0"))]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if busy[0] > 0:
            busy[0] -= 1
            code, err = 503, "SlowDown"
        elif not auth:
            code, err = int(cfg["UNSIGNED"]), "AccessDenied"
        elif "Credential=%s/" % cfg["KEY"] in auth and auth.startswith("AWS4-HMAC-SHA256 "):
            code, err = int(cfg["SIGNED"]), "AccessDenied"
        else:
            code, err = 403, "InvalidAccessKeyId"
        body = b"<ListAllMyBucketsResult/>" if code == 200 else ("<Error><Code>%s</Code></Error>" % err).encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
EOF

# serve UNSIGNED=.. SIGNED=.. KEY=.. [BUSY=..]: (re)start the stand-in agent.
serve() {
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
    rm -f "$WORK/port"
    python3 -I "$WORK/server.py" "$WORK/port" "$@" &
    SERVER_PID=$!
    disown "$SERVER_PID" # no "Terminated" line when it is replaced
    for _ in $(seq 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
    LSOF_ADDR="127.0.0.1:$(cat "$WORK/port")"
}
stop_server() {
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    LSOF_ADDR=""
}

# fresh_agent [plist-format]: a new HOME, an agent plist holding the SMB
# settings, loaded into the stub launchd.
SMB_PASS='p@ss w0rd&<amp>"'
fresh_agent() {
    CASE="$WORK/case$((++CASES))"
    HOME_DIR="$CASE/home"
    LD_STATE="$CASE/launchd"
    mkdir -p "$HOME_DIR/Library/LaunchAgents" "$LD_STATE"
    PLIST="$HOME_DIR/Library/LaunchAgents/$LABEL.plist"
    cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array><string>$WORK/bindir/spiceio</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SPICEIO_SMB_SERVER</key><string>nas.local</string>
    <key>SPICEIO_SMB_USER</key><string>svc$CASES</string>
    <key>SPICEIO_SMB_PASS</key><string>p@ss w0rd&amp;&lt;amp&gt;"</string>
    <key>SPICEIO_SMB_PASS_KEYCHAIN_PATH</key><string>$ITEMS</string>
  </dict>
</dict>
</plist>
EOF
    chmod 600 "$PLIST"
    [[ "${1:-xml1}" == xml1 ]] || plutil -convert "$1" "$PLIST"
    LD_STATE="$LD_STATE" "$WORK/bin/launchctl" bootstrap "gui/$(id -u)" "$PLIST"
    : >"$LD_STATE/calls"
    CREDS="$HOME_DIR/.config/spiceio/credentials"
}
CASES=0

# install_agent [VAR=value ...]: run agent-install.sh against the current case.
# OUT gets its output, RC its exit status.
install_agent() {
    : >"$LD_STATE/calls"
    set +e
    OUT=$(env -i PATH="$WORK/bin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$HOME_DIR" TMPDIR="$CASE" \
        LD_STATE="$LD_STATE" LSOF_ADDR="${LSOF_ADDR:-}" \
        BINDIR="$WORK/bindir" LAUNCHD_LABEL="$LABEL" AGENT_WAIT_SECS=1 \
        "$@" "$ROOT/scripts/agent-install.sh" 2>&1)
    RC=$?
    set -e
}
# preflight_agent BIN [VAR=value ...]: agent-install.sh --preflight BIN.
preflight_agent() {
    local bin=$1
    shift
    set +e
    OUT=$(env -i PATH="$WORK/bin:/usr/bin:/bin:/usr/sbin:/sbin" HOME="$HOME_DIR" TMPDIR="$CASE" \
        LD_STATE="$LD_STATE" BINDIR="$WORK/bindir" LAUNCHD_LABEL="$LABEL" \
        "$@" "$ROOT/scripts/agent-install.sh" --preflight "$bin" 2>&1)
    RC=$?
    set -e
}
# case_smb CMD...: CMD with the SMB settings this case's item is keyed on.
case_smb() {
    env -i PATH=/usr/bin:/bin HOME="$HOME_DIR" SPICEIO_SMB_SERVER=nas.local SPICEIO_SMB_USER="svc$CASES" \
        SPICEIO_SMB_PASS_KEYCHAIN="${SERVICE:-ai.spice.spiceio.smb}" SPICEIO_SMB_PASS_KEYCHAIN_PATH="$ITEMS" "$@"
}
# The case's item holds exactly $SMB_PASS (storing it again changes nothing).
item_holds_password() {
    printf '%s' "$SMB_PASS" | case_smb "$WORK/bindir/spiceio" --store-smb-password 2>&1 | grep -q ': unchanged in'
}
loaded_job_lacks_password() { ! grep -q 'SPICEIO_SMB_PASS =>' "$LD_STATE/env"; }
calls() { grep -v '^print' "$LD_STATE/calls" | cut -d' ' -f1 | tr '\n' ' ' | sed 's/ $//'; }
env_of() { plutil -extract "EnvironmentVariables.$1" raw -o - "$PLIST" 2>/dev/null; }
mode_of() { stat -f '%Lp' "$1"; }

echo "--- sccache-spiceio"
W="$WORK/bindir/sccache-spiceio"
WH="$WORK/wrapper-home"
mkdir -p "$WH/.config/spiceio"
printf '# comment\n\n  # indented comment\nold-key old-secret-0123456789\nnew-key new-secret-0123456789' >"$WH/.config/spiceio/credentials"
wrap() { env -i PATH=/usr/bin:/bin HOME="$WH" "$@"; }
OUT=$(wrap SPICEIO_SCCACHE=env "$W")
check "signs with the last key" has "AWS_ACCESS_KEY_ID=new-key"
check "even when its line has no trailing newline" has "AWS_SECRET_ACCESS_KEY=new-secret-0123456789"
OUT=$(wrap AWS_PROFILE=real-aws AWS_SESSION_TOKEN=tok SCCACHE_S3_NO_CREDENTIALS=1 SPICEIO_SCCACHE=env "$W")
check "drops SCCACHE_S3_NO_CREDENTIALS" lacks "SCCACHE_S3_NO_CREDENTIALS"
check "drops AWS_SESSION_TOKEN (spiceio refuses session tokens)" lacks "AWS_SESSION_TOKEN"
check "leaves AWS_PROFILE for everything else" has "AWS_PROFILE=real-aws"
printf 'other-key other-secret-0123456789\n' >"$WORK/other-creds"
OUT=$(wrap SPICEIO_CLIENT_CREDENTIALS_FILE="$WORK/other-creds" SPICEIO_SCCACHE=printenv "$W" AWS_ACCESS_KEY_ID)
check "SPICEIO_CLIENT_CREDENTIALS_FILE overrides the default file" [ "$OUT" = other-key ]
OUT=$(wrap SPICEIO_SCCACHE=printf "$W" '%s|' a 'b c' '')
check "passes its arguments through untouched" [ "$OUT" = "a|b c||" ]
set +e
OUT=$(env -i PATH=/usr/bin:/bin HOME="$WORK/nowhere" SPICEIO_SCCACHE=true "$W" 2>&1)
RC=$?
set -e
check "fails without a key instead of running sccache unsigned" [ "$RC" -eq 1 ]
check "says where it looked" has "no access key in $WORK/nowhere/.config/spiceio/credentials"

echo "--- first install wires SigV4 into the agent"
fresh_agent
serve UNSIGNED=403 SIGNED=200 KEY="local-$(hostname -s | tr 'A-Z' 'a-z' | tr -c 'a-z0-9.\n-' '-')"
install_agent
check "exits 0" [ "$RC" -eq 0 ]
check "creates the key file 0600" [ "$(mode_of "$CREDS")" = 600 ]
check "creates its directory 0700" [ "$(mode_of "$(dirname "$CREDS")")" = 700 ]
check "with exactly one key" [ "$(grep -cv '^#' "$CREDS")" -eq 1 ]
check "points the agent at it" [ "$(env_of SPICEIO_S3_CREDENTIALS_FILE)" = "$CREDS" ]
check "sets SPICEIO_S3_AUTH=enforce" [ "$(env_of SPICEIO_S3_AUTH)" = enforce ]
check "takes the SMB password out of the plist" [ -z "$(env_of SPICEIO_SMB_PASS)" ]
check "points the agent at the keychain item" [ "$(env_of SPICEIO_SMB_PASS_KEYCHAIN)" = ai.spice.spiceio.smb ]
check "keeps the keychain path it names" [ "$(env_of SPICEIO_SMB_PASS_KEYCHAIN_PATH)" = "$ITEMS" ]
check "stores it byte for byte" item_holds_password
check "the reloaded job no longer holds it" loaded_job_lacks_password
check "says it moved it" has "SMB password moved to the keychain"
check "warns that older copies of the plist still hold it" has "still hold the SMB password"
check "never prints the SMB password" lacks "$SMB_PASS"
check "nor the SMB user" lacks "svc$CASES"
check "keeps the plist's mode" [ "$(mode_of "$PLIST")" = 600 ]
check "leaves no temp file beside the plist" [ "$(find "$(dirname "$PLIST")" -name '.*' -type f | wc -l | tr -d ' ')" = 0 ]
check "reloads rather than kickstarts (kickstart keeps the old env)" [ "$(calls)" = "bootout bootstrap" ]
check "reports unsigned refused" has "unsigned requests refused (403)"
check "reports the wrapper's key accepted" has "(sccache-spiceio's key) accepted (200)"
check "notes the short exit timeout" has "SIGKILLs $LABEL 5s after SIGTERM"
check "never prints the secret" lacks "$(awk '!/^#/ {print $2}' "$CREDS")"
KEY_BEFORE=$(cat "$CREDS")

echo "--- second install changes nothing"
cp -p "$PLIST" "$CASE/plist.before"
install_agent
check "exits 0" [ "$RC" -eq 0 ]
check "plist untouched" cmp -s "$PLIST" "$CASE/plist.before"
check "key untouched" [ "$(cat "$CREDS")" = "$KEY_BEFORE" ]
check "plain kickstart" [ "$(calls)" = kickstart ]
check "says unchanged" has "(unchanged)"

echo "--- AGENT_AUTH=log, staged with RESTART_AGENT=0, then applied"
# The running agent still enforces until it is reloaded.
serve UNSIGNED=403 SIGNED=200 KEY="$(awk '!/^#/ {print $1}' "$CREDS")"
install_agent AGENT_AUTH=log RESTART_AGENT=0
check "exits 0: the old agent is not held to the new setting" [ "$RC" -eq 0 ]
check "says it did not check" has "not checked against AGENT_AUTH=log: the running agent predates its plist"
check "lists only what changed" has "plist: SPICEIO_S3_AUTH enforce -> log"
check "not the unchanged credentials file" lacks "SPICEIO_S3_CREDENTIALS_FILE $CREDS -> "
check "plist says log" [ "$(env_of SPICEIO_S3_AUTH)" = log ]
check "RESTART_AGENT=0 touches no job" [ -z "$(calls)" ]
check "says a reload is pending" has "applies only on a reload"
serve UNSIGNED=200 SIGNED=200 KEY="$(awk '!/^#/ {print $1}' "$CREDS")"
install_agent AGENT_AUTH=log
check "a later install sees the loaded job is stale and reloads it" [ "$(calls)" = "bootout bootstrap" ]
check "log serving unsigned requests is not an error" [ "$RC" -eq 0 ]

echo "--- this shell's sccache is unsigned"
install_agent AGENT_AUTH=log RUSTC_WRAPPER=/opt/homebrew/bin/sccache SCCACHE_S3_NO_CREDENTIALS=1
check "points at the wrapper" has "export RUSTC_WRAPPER=\"$WORK/bindir/sccache-spiceio\""
install_agent AGENT_AUTH=log RUSTC_WRAPPER="$WORK/bindir/sccache-spiceio"
check "quiet once RUSTC_WRAPPER is the wrapper" lacks "RUSTC_WRAPPER="

echo "--- the check holds the agent to AGENT_AUTH"
serve UNSIGNED=200 SIGNED=200 KEY="$(awk '!/^#/ {print $1}' "$CREDS")"
install_agent
check "enforce, yet unsigned served: fails" [ "$RC" -eq 1 ]
check "and says something overrides it" has "overrides it"
serve UNSIGNED=403 SIGNED=403 KEY="$(awk '!/^#/ {print $1}' "$CREDS")"
install_agent
check "wrapper's key refused: fails" [ "$RC" -eq 1 ]
check "and names both files" has "does not accept sccache-spiceio's key"
serve UNSIGNED=403 SIGNED=200 KEY=someone-else
install_agent
check "a key the agent does not know: reports its error code" has "got 403 InvalidAccessKeyId"
serve UNSIGNED=403 SIGNED=200 KEY="$(awk '!/^#/ {print $1}' "$CREDS")" BUSY=100000
install_agent
check "SMB never ready: a note, not a failure" [ "$RC" -eq 0 ]
check "says it could not check" has "could not check $LABEL's S3 auth: it answered 503"
stop_server
install_agent
check "not listening: a note, not a failure" [ "$RC" -eq 0 ]
check "says so" has "is not listening yet"

echo "--- AGENT_AUTH=keep"
fresh_agent
cp -p "$PLIST" "$CASE/plist.before"
install_agent AGENT_AUTH=keep AGENT_SMB_PASS=keep
check "exits 0" [ "$RC" -eq 0 ]
check "plist untouched" cmp -s "$PLIST" "$CASE/plist.before"
check "no key created" [ ! -e "$CREDS" ]
check "plain kickstart" [ "$(calls)" = kickstart ]

echo "--- an agent that already names a credentials file"
fresh_agent
mkdir -p "$CASE/elsewhere"
printf 'theirs 0123456789abcdef0123\n' >"$CASE/elsewhere/keys"
chmod 600 "$CASE/elsewhere/keys"
plutil -replace EnvironmentVariables.SPICEIO_S3_CREDENTIALS_FILE -string "$CASE/elsewhere/keys" "$PLIST"
install_agent
check "keeps pointing at it" [ "$(env_of SPICEIO_S3_CREDENTIALS_FILE)" = "$CASE/elsewhere/keys" ]
check "never rewrites it" [ "$(cat "$CASE/elsewhere/keys")" = "theirs 0123456789abcdef0123" ]
check "creates no default key" [ ! -e "$CREDS" ]
chmod 644 "$CASE/elsewhere/keys"
plutil -replace EnvironmentVariables.SPICEIO_S3_AUTH -string log "$PLIST"
cp -p "$PLIST" "$CASE/plist.before"
install_agent
check "group-readable key file: fails before touching anything" [ "$RC" -eq 1 ]
check "with the server's own reason" has "chmod 600 it"
check "plist untouched" cmp -s "$PLIST" "$CASE/plist.before"
check "no restart" [ -z "$(calls)" ]
plutil -replace EnvironmentVariables.SPICEIO_S3_CREDENTIALS_FILE -string "~/keys" "$PLIST"
install_agent
check "a relative path (launchd does not expand ~): fails" [ "$RC" -eq 1 ]
check "and says why" has "not an absolute path"

echo "--- plist formats and locations"
fresh_agent binary1
install_agent
check "a binary plist stays binary" grep -q "Apple binary property list" <<<"$(file "$PLIST")"
check "and is wired" [ "$(env_of SPICEIO_S3_AUTH)" = enforce ]
check "and its SMB password moved" [ "$(env_of SPICEIO_SMB_PASS_KEYCHAIN)" = ai.spice.spiceio.smb ]
check "out of the binary plist" [ -z "$(env_of SPICEIO_SMB_PASS)" ]
fresh_agent
mkdir -p "$CASE/dotfiles"
mv "$PLIST" "$CASE/dotfiles/agent.plist"
ln -s "$CASE/dotfiles/agent.plist" "$PLIST"
install_agent
check "a symlinked plist stays a symlink" [ -L "$PLIST" ]
check "and its target is edited" [ "$(plutil -extract EnvironmentVariables.SPICEIO_S3_AUTH raw -o - "$CASE/dotfiles/agent.plist")" = enforce ]

echo "--- nothing to do"
fresh_agent
rm -f "$LD_STATE/loaded"
install_agent
check "no agent loaded: exits 0" [ "$RC" -eq 0 ]
check "says so" has "no launchd agent $LABEL is loaded"
check "creates no key" [ ! -e "$CREDS" ]
install_agent AGENT_AUTH=sometimes
check "unknown AGENT_AUTH: fails" [ "$RC" -eq 1 ]
install_agent AGENT_SMB_PASS=sometimes
check "unknown AGENT_SMB_PASS: fails" [ "$RC" -eq 1 ]
preflight_agent "$WORK/adhocbin/spiceio"
check "preflight with no agent loaded: passes" [ "$RC" -eq 0 ]

echo "--- AGENT_SMB_PASS=keep"
fresh_agent
install_agent AGENT_SMB_PASS=keep
check "exits 0" [ "$RC" -eq 0 ]
check "the password stays in the plist" [ "$(env_of SPICEIO_SMB_PASS)" = "$SMB_PASS" ]
check "no keychain service set" [ -z "$(env_of SPICEIO_SMB_PASS_KEYCHAIN)" ]
OUT=$(case_smb "$WORK/bindir/spiceio" --check-smb-password 2>&1 || true)
check "and no item stored" has "no keychain item"

echo "--- the plist names its own keychain service"
fresh_agent
plutil -replace EnvironmentVariables.SPICEIO_SMB_PASS_KEYCHAIN -string ai.spice.custom "$PLIST"
install_agent
check "exits 0" [ "$RC" -eq 0 ]
check "keeps that service" [ "$(env_of SPICEIO_SMB_PASS_KEYCHAIN)" = ai.spice.custom ]
check "and drops the inline password (both set is a startup error)" [ -z "$(env_of SPICEIO_SMB_PASS)" ]
SERVICE=ai.spice.custom
check "stores it under that service" item_holds_password
unset SERVICE

echo "--- an item that already holds an older password"
fresh_agent
printf 'an-old-password' | case_smb "$WORK/bindir/spiceio" --store-smb-password >/dev/null
install_agent
check "exits 0" [ "$RC" -eq 0 ]
check "the plist's password wins" has ": updated in keychain item"
check "and is what the item holds now" item_holds_password

echo "--- the keychain cannot take it"
fresh_agent
security lock-keychain "$ITEMS"
cp -p "$PLIST" "$CASE/plist.before"
install_agent
check "fails" [ "$RC" -eq 1 ]
check "says it could not store it" has "could not be stored in the keychain"
check "and why" has "is locked"
check "plist untouched: the password stays where it was" [ "$(env_of SPICEIO_SMB_PASS)" = "$SMB_PASS" ]
check "no restart" [ -z "$(calls)" ]
check "never prints the SMB password" lacks "$SMB_PASS"
security unlock-keychain -p items-pw "$ITEMS"

echo "--- an agent already on the keychain"
fresh_agent
install_agent
check "migrates" [ "$RC" -eq 0 ]
install_agent
check "a second install leaves it" has "SMB password from keychain item \"ai.spice.spiceio.smb\" (unchanged)"
security lock-keychain "$ITEMS"
install_agent
check "an unreadable item fails the install" [ "$RC" -eq 1 ]
check "before any restart" [ -z "$(calls)" ]
check "and says why" has "could not read its SMB password, so it is not being restarted"
install_agent AGENT_SMB_PASS=keep
check "even with AGENT_SMB_PASS=keep" [ "$RC" -eq 1 ]
check "which restarts nothing either" [ -z "$(calls)" ]
security unlock-keychain -p items-pw "$ITEMS"

echo "--- preflight: a new build must read the agent's password before it is installed"
sign "$WORK/rebuilt" kill
preflight_agent "$WORK/rebuilt"
check "another build signed with the same identity: passes" [ "$RC" -eq 0 ]
preflight_agent "$WORK/adhocbin/spiceio"
check "an ad-hoc build: fails" [ "$RC" -eq 1 ]
check "says the running binary is unchanged" has "The running binary is unchanged"
check "and why" has "is not on the item's access list"
fresh_agent
preflight_agent "$WORK/adhocbin/spiceio"
check "an agent still holding its password inline: nothing to check" [ "$RC" -eq 0 ]

echo "--- an empty SPICEIO_SMB_PASS counts as unset, as it does at startup"
fresh_agent
install_agent
check "migrates" [ "$RC" -eq 0 ]
plutil -insert EnvironmentVariables.SPICEIO_SMB_PASS -string "" "$PLIST"
preflight_agent "$WORK/adhocbin/spiceio"
check "preflight still checks the keychain item (refuses an ad-hoc build)" [ "$RC" -eq 1 ]
install_agent
check "install treats the agent as keychain-backed" [ "$RC" -eq 0 ]
check "and does not try to migrate an empty password" has "SMB password from keychain item \"ai.spice.spiceio.smb\" (unchanged)"

echo "--- a password that starts with a newline is a password, not an empty value"
fresh_agent
plutil -replace EnvironmentVariables.SPICEIO_SMB_PASS -string $'\nleading-newline' "$PLIST"
install_agent
check "migrates it" [ -z "$(env_of SPICEIO_SMB_PASS)" ]
check "to the keychain" [ "$(env_of SPICEIO_SMB_PASS_KEYCHAIN)" = ai.spice.spiceio.smb ]

echo "--- preflight cannot read the loaded agent's plist"
fresh_agent
install_agent
mv "$PLIST" "$CASE/away.plist"
preflight_agent "$WORK/bindir/spiceio"
check "plist gone: fails" [ "$RC" -eq 1 ]
check "and says why" has "cannot read $LABEL's plist"
mv "$CASE/away.plist" "$PLIST"
cp -p "$PLIST" "$CASE/good.plist"
printf 'not a plist' >"$PLIST"
preflight_agent "$WORK/bindir/spiceio"
check "plist unparsable: fails" [ "$RC" -eq 1 ]
cp -p "$CASE/good.plist" "$PLIST"
preflight_agent "$WORK/bindir/spiceio"
check "plist back: passes" [ "$RC" -eq 0 ]

echo "--- a new signing identity: store with it first, then install (README)"
fresh_agent
install_agent
check "migrates with the current identity" [ "$RC" -eq 0 ]
setup "create a second signing identity" env PTY_PASSWORD=rotated-pw \
    SIGNING_KEYCHAIN="$WORK/rotated-signing.keychain-db" python3 -I "$PTY" \
    sh "$ROOT/scripts/codesign-local.sh" "$SPICEIO_BIN" "$WORK/rotated"
# Deleting the old item would ask for the login password; naming a service
# that holds nothing is the same state for preflight.
plutil -replace EnvironmentVariables.SPICEIO_SMB_PASS_KEYCHAIN -string ai.spice.rotated "$PLIST"
preflight_agent "$WORK/rotated"
check "with the old item gone, install refuses the new build" [ "$RC" -eq 1 ]
OUT=$(printf '%s' "$SMB_PASS" | SERVICE=ai.spice.rotated case_smb "$WORK/rotated" --store-smb-password 2>&1)
check "the new build stores the password" has ": added in keychain item \"ai.spice.rotated\""
preflight_agent "$WORK/rotated"
check "and then install accepts it" [ "$RC" -eq 0 ]
preflight_agent "$WORK/bindir/spiceio"
check "while the old identity's build is refused" [ "$RC" -eq 1 ]

echo "--- an ad-hoc installed binary does not take the password"
fresh_agent
install_agent BINDIR="$WORK/adhocbin"
check "exits 0" [ "$RC" -eq 0 ]
check "says why not" has "is ad-hoc"
check "the password stays in the plist" [ "$(env_of SPICEIO_SMB_PASS)" = "$SMB_PASS" ]

check "leaves the keychain search list as it found it" search_list_kept "$SEARCH_LIST_BEFORE" "$WORK"

echo ""
echo "agent-install: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
