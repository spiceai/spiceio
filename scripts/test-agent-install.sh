#!/usr/bin/env bash
# Hermetic tests for `make install`'s launchd half (scripts/agent-install.sh)
# and the sccache-spiceio wrapper. No launchd agent is touched: `launchctl`
# and `lsof` are stubs on PATH that record what they were asked to do. A small
# local HTTP server stands in for the agent when the post-restart check needs
# answers. plutil, curl, openssl and `spiceio --check-auth` are the real ones,
# so the plist edits and the auth validation are exactly what an install does.
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
SERVER_PID=""
cleanup() {
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
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
mkdir -p "$WORK/bin" "$WORK/bindir"
ln -s "$SPICEIO_BIN" "$WORK/bindir/spiceio"
install -m 0755 "$ROOT/scripts/sccache-spiceio" "$WORK/bindir/sccache-spiceio"

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
    <key>SPICEIO_SMB_PASS</key><string>p@ss w0rd&amp;&lt;amp&gt;"</string>
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
check "keeps the SMB password byte for byte" [ "$(env_of SPICEIO_SMB_PASS)" = "$SMB_PASS" ]
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
install_agent AGENT_AUTH=keep
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

echo ""
echo "agent-install: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
