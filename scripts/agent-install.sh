#!/bin/sh
# The launchd half of `make install`, run after the binary is in place:
#
#   1. Wire SigV4 into the agent. Create an access key if the agent has no
#      credentials file yet, then set SPICEIO_S3_CREDENTIALS_FILE and
#      SPICEIO_S3_AUTH in the agent's plist.
#   2. Move the agent's SMB password out of its plist and into the keychain:
#      store it with the installed (signed) `spiceio --store-smb-password`,
#      prove the agent could read it with `--check-smb-password`, then
#      replace SPICEIO_SMB_PASS with SPICEIO_SMB_PASS_KEYCHAIN.
#   3. Restart the agent on the new binary. If its plist environment differs
#      from what launchd loaded, reload it instead (kickstart reuses the
#      loaded definition).
#   4. Report where it listens and check what it accepts: an unsigned request
#      should be refused, and a request signed through sccache-spiceio
#      should be served.
#
#   agent-install.sh --preflight BIN
#
# checks, before `make install` puts BIN in place, that BIN can read the
# agent's SMB password from the keychain (when the agent takes it from
# there). A build that cannot would leave the agent unable to start, so the
# install stops and the running binary stays.
#
# Settings come from the environment (the Makefile passes all of them):
#
#   BINDIR               where spiceio and sccache-spiceio were just installed
#   LAUNCHD_LABEL        the agent's label
#   RESTART_AGENT        0: leave the running agent alone, say what would restart it
#   AGENT_AUTH           enforce | log | off: the SPICEIO_S3_AUTH to set.
#                        keep: leave the agent's auth settings and key alone
#   S3_CREDENTIALS_FILE  the key file to use when the agent names none
#   AGENT_SMB_PASS       keychain (default): move an SMB password in the plist
#                        into the keychain. keep: leave it where it is
#   SMB_PASS_KEYCHAIN_SERVICE  the keychain service to use when the plist names
#                        none (ai.spice.spiceio.smb)
#   AGENT_WAIT_SECS      how long to wait for the agent to listen, and then for
#                        SMB to come up, before giving up on the check (30)
#
# Install only fills in what is missing. It never rewrites a credentials file,
# and it never repoints an agent that already names one: other clients may
# sign with the keys in it. The plist can hold the SMB password, so it is
# edited on a copy in its own directory and renamed into place. A failed edit
# leaves the original intact, and the copy keeps the original's mode. The
# password itself only ever travels through a pipe, from plutil to spiceio:
# never through a shell variable, an argument list or the output.
#
# Exit status: nonzero when a restart fails, when the new auth configuration
# would stop the agent from starting (checked with `spiceio --check-auth`
# first, so the running agent is left alone), when the agent's SMB password
# cannot be stored in or read from the keychain, or when the check shows the
# agent does not behave the way AGENT_AUTH asked. "Not listening yet" and
# "SMB still connecting" are notes, not failures.
set -u

: "${BINDIR:?}" "${LAUNCHD_LABEL:?}"
RESTART_AGENT="${RESTART_AGENT:-1}"
AGENT_AUTH="${AGENT_AUTH:-enforce}"
S3_CREDENTIALS_FILE="${S3_CREDENTIALS_FILE:-$HOME/.config/spiceio/credentials}"
AGENT_SMB_PASS="${AGENT_SMB_PASS:-keychain}"
SMB_PASS_KEYCHAIN_SERVICE="${SMB_PASS_KEYCHAIN_SERVICE:-ai.spice.spiceio.smb}"
AGENT_WAIT_SECS="${AGENT_WAIT_SECS:-30}"

uid=$(id -u)
domain="gui/$uid"
target="$domain/$LAUNCHD_LABEL"
wrapper="$BINDIR/sccache-spiceio"
status=0
tmp=""
trap '[ -z "$tmp" ] || rm -f "$tmp"' EXIT
trap 'exit 130' INT TERM

die() {
    echo "error: $*" >&2
    exit 1
}

case "$AGENT_AUTH" in
enforce | log | off | keep) ;;
*) die "AGENT_AUTH=$AGENT_AUTH: expected enforce, log, off or keep" ;;
esac
case "$AGENT_SMB_PASS" in
keychain | keep) ;;
*) die "AGENT_SMB_PASS=$AGENT_SMB_PASS: expected keychain or keep" ;;
esac

# `launchctl print` of the loaded job, or failure when none is loaded.
agent_print() { launchctl print "$target" 2>/dev/null; }

# A top-level `key = value` field of the loaded job (pid, path, exit timeout).
agent_field() {
    agent_print | awk -v k="$1" -F' = ' '$1 == "\t" k { print substr($0, length(k) + 5); exit }'
}

# The value the *loaded* job has for an environment variable. launchd reads
# the plist only at load time, so this is what the running process got.
loaded_env() {
    agent_print | awk -v k="$1" '
        $0 == "\tenvironment = {" { inside = 1; next }
        inside && $0 == "\t}" { exit }
        inside && index($0, "\t\t" k " => ") == 1 { print substr($0, length(k) + 7); found = 1; exit }
        END { exit !found }'
}

# The names of the SPICEIO_* variables the loaded job has.
loaded_spiceio_vars() {
    agent_print | awk '
        $0 == "\tenvironment = {" { inside = 1; next }
        inside && $0 == "\t}" { exit }
        inside && $1 ~ /^SPICEIO_/ && $2 == "=>" { print $1 }'
}

# A value from the plist, or failure when the key path is absent.
plist_get() { plutil -extract "$2" raw -o - "$1" 2>/dev/null; }

# The plist's EnvironmentVariables names, one per line.
plist_env_names() {
    plutil -extract EnvironmentVariables raw -o - "$1" 2>/dev/null || true
}

# True when the loaded job's environment differs from its plist's, so a
# kickstart would restart it on stale settings.
loaded_env_is_stale() {
    for name in $(plist_env_names "$1"); do
        want=$(plist_get "$1" "EnvironmentVariables.$name") || continue
        have=$(loaded_env "$name") || return 0
        [ "$have" = "$want" ] || return 0
    done
    # A SPICEIO_* variable removed from the plist is still set in the job.
    for name in $(loaded_spiceio_vars); do
        plist_get "$1" "EnvironmentVariables.$name" >/dev/null || return 0
    done
    return 1
}

# Create the key file with one fresh access key, unless it already exists.
# An existing file is never rewritten; `spiceio --check-auth` validates it.
provision_key() {
    f=$1
    [ -e "$f" ] || [ -L "$f" ] && return 0
    d=$(dirname "$f")
    if [ ! -d "$d" ]; then
        (umask 077 && mkdir -p "$d") || die "cannot create $d"
    fi
    host=$(hostname -s 2>/dev/null | tr 'A-Z' 'a-z' | tr -c 'a-z0-9.\n-' '-')
    id="local${host:+-$host}"
    # 32 random bytes as hex: well over the 16-character minimum, and no
    # character that needs quoting in a shell, a curl option or an INI file.
    secret=$(openssl rand -hex 32) || die "openssl rand failed"
    [ "${#secret}" -eq 64 ] || die "openssl rand returned an unexpected secret"
    tmp=$(mktemp "$d/.spiceio-credentials.XXXXXX") || die "cannot create a file in $d"
    {
        echo "# spiceio S3 access keys: ACCESS_KEY_ID SECRET_ACCESS_KEY, one per line."
        echo "# Created by \`make install\`. The launchd agent accepts every key listed;"
        echo "# sccache-spiceio signs with the last one. Keep this file mode 0600."
        printf '%s %s\n' "$id" "$secret"
    } >"$tmp" || die "cannot write $tmp"
    # A hard link publishes the file only if nothing is there yet, so a
    # concurrent install cannot replace a key a client already signs with.
    # mktemp already created it 0600.
    if ln "$tmp" "$f" 2>/dev/null; then
        echo "created access key $id in $f"
    fi
    rm -f "$tmp"
    tmp=""
    [ -e "$f" ] || die "could not create $f"
}

# Resolve the S3 auth settings the agent would start with, the way it would
# resolve them. That means the plist's inline keys plus the credentials file
# and mode about to be written, evaluated from the agent's working directory.
check_auth() {
    (
        unset SPICEIO_S3_ACCESS_KEY_ID SPICEIO_S3_SECRET_ACCESS_KEY \
            SPICEIO_S3_CREDENTIALS_FILE SPICEIO_S3_AUTH
        for name in SPICEIO_S3_ACCESS_KEY_ID SPICEIO_S3_SECRET_ACCESS_KEY; do
            # `export` is a builtin, so an inline secret never lands in argv.
            if value=$(plist_get "$1" "EnvironmentVariables.$name"); then
                export "$name=$value"
            fi
        done
        export SPICEIO_S3_CREDENTIALS_FILE="$2" SPICEIO_S3_AUTH="$3"
        cd "$(plist_get "$1" WorkingDirectory || echo /)" 2>/dev/null || cd /
        exec "$BINDIR/spiceio" --check-auth
    )
}

# Set SPICEIO_S3_CREDENTIALS_FILE and SPICEIO_S3_AUTH in the agent's plist.
# edit_plist FILE NOTE EDIT: run EDIT (a function, given the copy's path) on a
# copy of FILE in FILE's own directory, lint the copy, then rename it over
# FILE. The plist can hold the SMB password, so it is never edited in place:
# a failed edit leaves FILE as it was (NOTE says what else holds then), and
# the copy keeps FILE's mode. FILE is a resolved path, so a symlinked plist
# keeps its link and its target is what changes.
edit_plist() {
    dir=$(dirname "$1")
    tmp=$(mktemp "$dir/.$(basename "$1").XXXXXX") || die "cannot create a file in $dir"
    cp -p "$1" "$tmp" || die "cannot copy $1"
    "$3" "$tmp" && plutil -lint -s "$tmp" || die "cannot edit $1 (left unchanged$2)"
    mv -f "$tmp" "$1" || die "cannot replace $1 (left unchanged$2)"
    tmp=""
}

wire_auth() {
    plist=$1
    # Edit what a symlinked plist points at (a dotfiles checkout, say). A
    # rename over the link would replace it with a copy.
    file=$(realpath "$plist") || die "cannot resolve $plist"
    dir=$(dirname "$file")
    current_file=$(plist_get "$file" EnvironmentVariables.SPICEIO_S3_CREDENTIALS_FILE) || current_file=""
    current_auth=$(plist_get "$file" EnvironmentVariables.SPICEIO_S3_AUTH) || current_auth=""
    creds=${current_file:-$S3_CREDENTIALS_FILE}
    case "$creds" in
    /*) ;;
    *) die "credentials file \"$creds\" is not an absolute path (launchd expands neither ~ nor \$HOME)" ;;
    esac

    if [ "$current_file" = "$creds" ] && [ "$current_auth" = "$AGENT_AUTH" ]; then
        provision_key "$creds"
        summary=$(check_auth "$file" "$creds" "$AGENT_AUTH" 2>&1) ||
            die "$LAUNCHD_LABEL would not start with its current auth settings: $summary"
        echo "$LAUNCHD_LABEL plist: SPICEIO_S3_AUTH=$AGENT_AUTH, keys from $creds (unchanged)"
        return
    fi

    [ -w "$file" ] && [ -w "$dir" ] || die "$file is not writable. Add these to its EnvironmentVariables yourself:
         SPICEIO_S3_CREDENTIALS_FILE = $creds
         SPICEIO_S3_AUTH = $AGENT_AUTH"
    provision_key "$creds"
    summary=$(check_auth "$file" "$creds" "$AGENT_AUTH" 2>&1) ||
        die "not changing $LAUNCHD_LABEL: with these settings it would refuse to start: $summary"

    edit_plist "$file" "" auth_edits
    changes=""
    [ "$current_auth" = "$AGENT_AUTH" ] ||
        changes="SPICEIO_S3_AUTH ${current_auth:-(unset)} -> $AGENT_AUTH"
    [ "$current_file" = "$creds" ] ||
        changes="${changes:+$changes, }SPICEIO_S3_CREDENTIALS_FILE ${current_file:-(unset)} -> $creds"
    echo "$LAUNCHD_LABEL plist: $changes"
    echo "  ($summary)"
}

# The SigV4 settings, applied to the plist copy $1.
auth_edits() {
    if ! plist_get "$1" EnvironmentVariables >/dev/null; then
        plutil -insert EnvironmentVariables -dictionary "$1" || return
    fi
    plutil -replace EnvironmentVariables.SPICEIO_S3_CREDENTIALS_FILE -string "$creds" "$1" &&
        plutil -replace EnvironmentVariables.SPICEIO_S3_AUTH -string "$AGENT_AUTH" "$1"
}

# Run a command with the SMB settings of plist $1 that decide which keychain
# item holds the password (and none of the caller's), with
# SPICEIO_SMB_PASS_KEYCHAIN=$2 and no SPICEIO_SMB_PASS.
with_smb_env() {
    p=$1
    service=$2
    shift 2
    (
        for name in SPICEIO_SMB_SERVER SPICEIO_SMB_USER SPICEIO_SMB_DOMAIN SPICEIO_SMB_PORT \
            SPICEIO_SMB_PASS_KEYCHAIN_PATH; do
            unset "$name"
            if value=$(plist_get "$p" "EnvironmentVariables.$name"); then
                export "$name=$value"
            fi
        done
        unset SPICEIO_SMB_PASS
        export SPICEIO_SMB_PASS_KEYCHAIN="$service"
        exec "$@"
    )
}

# True when plist $1 sets a non-empty SPICEIO_SMB_PASS. Startup treats an
# empty value as unset, so this must too. `plutil -extract … raw` prints the
# value and a newline (only the newline when empty, nothing when missing), so
# more than one byte means a password, whatever it starts with. Only the count
# leaves the pipe: the value is never held in a variable. (`-extract … json`
# refuses a bare string, so it cannot be used here.)
has_inline_pass() {
    bytes=$(plutil -extract EnvironmentVariables.SPICEIO_SMB_PASS raw -o - "$1" 2>/dev/null | wc -c | tr -d ' ')
    [ "${bytes:-0}" -gt 1 ]
}

# True when the plist takes the SMB password from the keychain (a non-empty
# SPICEIO_SMB_PASS_KEYCHAIN and no inline password), with the service on stdout.
keychain_service() {
    has_inline_pass "$1" && return 1
    service=$(plist_get "$1" EnvironmentVariables.SPICEIO_SMB_PASS_KEYCHAIN) || return 1
    [ -n "$service" ] || return 1
    printf '%s\n' "$service"
}

# Can binary $3 read the SMB password from the keychain item plist $1 names
# (service $2)? Its report on stdout either way.
smb_pass_readable() {
    with_smb_env "$1" "$2" "$3" --check-smb-password 2>&1
}

# Fail (without restarting anything) unless the installed binary can read the
# agent's SMB password from the keychain item its plist names.
require_readable_smb_pass() {
    summary=$(smb_pass_readable "$1" "$2" "$BINDIR/spiceio") ||
        die "$LAUNCHD_LABEL could not read its SMB password, so it is not being restarted: $summary"
}

# Replace SPICEIO_SMB_PASS with SPICEIO_SMB_PASS_KEYCHAIN=$service in the
# plist copy $1.
smb_pass_edits() {
    plutil -remove EnvironmentVariables.SPICEIO_SMB_PASS "$1" &&
        plutil -replace EnvironmentVariables.SPICEIO_SMB_PASS_KEYCHAIN -string "$service" "$1"
}

# Move the plist's SMB password into the keychain.
wire_smb_pass() {
    file=$1
    dir=$(dirname "$file")
    if service=$(keychain_service "$file"); then
        require_readable_smb_pass "$file" "$service"
        echo "$LAUNCHD_LABEL plist: SMB password from keychain item \"$service\" (unchanged)"
        return
    fi
    if ! has_inline_pass "$file"; then
        echo "note: $LAUNCHD_LABEL's plist sets neither SPICEIO_SMB_PASS nor SPICEIO_SMB_PASS_KEYCHAIN; leaving its SMB password alone"
        return
    fi
    # An item stored by an ad-hoc binary pins that binary's cdhash, so the
    # next build could not read it and the agent would not start.
    if codesign -dv "$BINDIR/spiceio" 2>&1 | grep -q '^CodeDirectory.*adhoc'; then
        echo "note: not moving $LAUNCHD_LABEL's SMB password into the keychain: $BINDIR/spiceio is ad-hoc"
        echo "      signed (CODESIGN=adhoc), so only this exact build could read it back."
        return
    fi
    [ -w "$file" ] && [ -w "$dir" ] || die "$file is not writable, so its SMB password stays in it.
       Store it yourself (spiceio --store-smb-password), then replace SPICEIO_SMB_PASS
       with SPICEIO_SMB_PASS_KEYCHAIN = $SMB_PASS_KEYCHAIN_SERVICE in its EnvironmentVariables."
    service=$(plist_get "$file" EnvironmentVariables.SPICEIO_SMB_PASS_KEYCHAIN) || service=""
    [ -n "$service" ] || service=$SMB_PASS_KEYCHAIN_SERVICE

    # plutil appends a newline, which --store-smb-password drops.
    stored=$(plutil -extract EnvironmentVariables.SPICEIO_SMB_PASS raw -o - "$file" |
        with_smb_env "$file" "$service" "$BINDIR/spiceio" --store-smb-password 2>&1) ||
        die "not changing $LAUNCHD_LABEL: its SMB password could not be stored in the keychain: $stored"
    summary=$(smb_pass_readable "$file" "$service" "$BINDIR/spiceio") ||
        die "not changing $LAUNCHD_LABEL: the stored SMB password does not read back: $summary"
    edit_plist "$file" "; the keychain item is in place" smb_pass_edits
    echo "$LAUNCHD_LABEL plist: SMB password moved to the keychain (SPICEIO_SMB_PASS removed, SPICEIO_SMB_PASS_KEYCHAIN=$service)"
    printf '%s\n' "$stored" | sed 's/^/  /'
    echo "note: copies of the plist made before now (Time Machine, other backups, a dotfiles repo)"
    echo "      still hold the SMB password. If any could have been read, change it on the NAS,"
    echo "      then store the new one: $BINDIR/spiceio --store-smb-password --server <server> --user <user>"
    echo "      (plus --domain/--port/--service if the agent sets them)"
}

# `--preflight BIN`: can BIN read the agent's SMB password? With no agent
# loaded there is nothing to protect. With one loaded, a plist that cannot be
# resolved, read or parsed is a failure, not a pass: whether BIN could read
# the password is then unknown, and installing could strand the agent.
if [ "${1:-}" = --preflight ]; then
    [ $# -eq 2 ] || die "usage: $0 --preflight BIN"
    agent_print >/dev/null || exit 0
    agent_plist=$(agent_field path)
    [ -n "$agent_plist" ] ||
        die "not installing: cannot tell which plist $LAUNCHD_LABEL was loaded from ($target)"
    file=$(realpath "$agent_plist" 2>/dev/null) && [ -r "$file" ] && plutil -lint -s "$file" >/dev/null 2>&1 ||
        die "not installing: cannot read $LAUNCHD_LABEL's plist ($agent_plist), so whether the new
       build can read its SMB password is unknown. The running binary is unchanged."
    service=$(keychain_service "$file") || exit 0
    summary=$(smb_pass_readable "$file" "$service" "$2") ||
        die "not installing: the new build cannot read $LAUNCHD_LABEL's SMB password from the
       keychain, so the agent could not start on it. The running binary is unchanged.
       $summary"
    exit 0
fi

# bootout returns before the job has exited: launchd sends SIGTERM and
# reports success while the process drains. A bootstrap issued in that window
# fails with "5: Input/output error", so wait for the job to disappear first.
reload_agent() {
    echo "reloading $LAUNCHD_LABEL to apply its plist (SIGTERM first, so it can drain)"
    launchctl bootout "$target" || return
    waited=0
    while agent_print >/dev/null; do
        if [ "$waited" -ge 600 ]; then # 0.2s ticks: two minutes
            echo "error: $LAUNCHD_LABEL is still stopping; bootstrap it once it exits:" >&2
            echo "         launchctl bootstrap $domain $1" >&2
            return 1
        fi
        sleep 0.2
        waited=$((waited + 1))
    done
    tries=0
    until launchctl bootstrap "$domain" "$1"; do
        tries=$((tries + 1))
        if [ "$tries" -ge 5 ]; then
            echo "error: $LAUNCHD_LABEL is unloaded and did not come back. Load it with:" >&2
            echo "         launchctl bootstrap $domain $1" >&2
            return 1
        fi
        sleep 0.5
    done
}

# curl options for every check: -q (first, or it is ignored) skips ~/.curlrc
# and --noproxy keeps a proxy from the environment out of a loopback request.
CURL_OPTS="-q --noproxy * -s --max-time 5"

# One request's status code; 000 when nothing answered.
http_code() {
    # shellcheck disable=SC2086 # CURL_OPTS is a list of options
    code=$(set -f && curl $CURL_OPTS -o /dev/null -w '%{http_code}' "$@" 2>/dev/null)
    echo "${code:-000}"
}

# Where the agent listens, then what it accepts.
report() {
    if ! agent_print >/dev/null; then
        echo "note: $LAUNCHD_LABEL is not loaded"
        return
    fi
    pid=""
    addrs=""
    ticks=$((AGENT_WAIT_SECS * 5))
    while [ "$ticks" -gt 0 ]; do
        pid=$(agent_field pid)
        if [ -n "$pid" ]; then
            # -b/-w: never block on (or warn about) a hung network mount while
            # lsof walks the mount table. lsof prints 0.0.0.0 as `*`.
            addrs=$(lsof -b -w -nP -a -p "$pid" -iTCP -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n//p' | sort -u)
            [ -n "$addrs" ] && break
        fi
        sleep 0.2
        ticks=$((ticks - 1))
    done
    if [ -z "$addrs" ]; then
        echo "note: $LAUNCHD_LABEL is not listening yet (pid ${pid:-none}); check its log"
        return
    fi

    exposed=""
    url=""
    for addr in $addrs; do
        case "$addr" in
        127.* | '[::1]':*) echo "$LAUNCHD_LABEL listening on http://$addr (loopback only)" ;;
        *)
            echo "$LAUNCHD_LABEL listening on $addr (reachable from other hosts)"
            exposed="$exposed $addr"
            ;;
        esac
        if [ -z "$url" ]; then
            case "$addr" in
            '*':*) url="http://127.0.0.1:${addr#*:}" ;;
            '[::]':*) url="http://[::1]:${addr##*:}" ;;
            *) url="http://$addr" ;;
            esac
        fi
    done

    # The agent answers 503 to everything, signed or not, until its SMB pool
    # is up. Any other answer to an unsigned request is the auth verdict.
    unsigned=000
    ticks=$((AGENT_WAIT_SECS * 2))
    while [ "$ticks" -gt 0 ]; do
        unsigned=$(http_code "$url/")
        case "$unsigned" in 000 | 503) ;; *) break ;; esac
        sleep 0.5
        ticks=$((ticks - 1))
    done

    region=$(plist_get "${agent_plist:-/dev/null}" EnvironmentVariables.SPICEIO_REGION) || region=us-east-1
    signed=""
    key_id=""
    signed_err=""
    case "$unsigned" in
    000 | 503) ;;
    *)
        # Sign through the installed wrapper, with curl standing in for
        # sccache. That checks the key it picks, not a copy of its logic.
        # `--variable %NAME` reads the key from curl's environment, so the
        # secret never appears in an argument list.
        if key_id=$(SPICEIO_SCCACHE=printenv "$wrapper" AWS_ACCESS_KEY_ID 2>/dev/null); then
            body=$(mktemp "${TMPDIR:-/tmp}/spiceio-probe.XXXXXX")
            # shellcheck disable=SC2086 # CURL_OPTS is a list of options
            signed=$(set -f && SPICEIO_SCCACHE=curl "$wrapper" $CURL_OPTS -o "$body" -w '%{http_code}' \
                --variable '%AWS_ACCESS_KEY_ID' --variable '%AWS_SECRET_ACCESS_KEY' \
                --expand-user '{{AWS_ACCESS_KEY_ID}}:{{AWS_SECRET_ACCESS_KEY}}' \
                --aws-sigv4 "aws:amz:$region:s3" "$url/" 2>/dev/null)
            signed=${signed:-000}
            signed_err=$(sed -n 's:.*<Code>\(.*\)</Code>.*:\1:p' "$body" | head -n 1)
            rm -f "$body"
        else
            signed_err=$(SPICEIO_SCCACHE=true "$wrapper" 2>&1 | head -n 1)
        fi
        ;;
    esac

    refused=0
    case "$unsigned" in
    000 | 503)
        echo "note: could not check $LAUNCHD_LABEL's S3 auth: it answered $unsigned for ${AGENT_WAIT_SECS}s (still connecting to SMB?)"
        ;;
    403)
        refused=1
        echo "$LAUNCHD_LABEL S3 auth: unsigned requests refused (403)"
        ;;
    *)
        echo "$LAUNCHD_LABEL S3 auth: unsigned requests served ($unsigned)"
        ;;
    esac
    if [ -n "$key_id" ]; then
        case "$signed" in
        200) echo "$LAUNCHD_LABEL S3 auth: requests signed as $key_id (sccache-spiceio's key) accepted (200)" ;;
        *) echo "$LAUNCHD_LABEL S3 auth: requests signed as $key_id (sccache-spiceio's key) got $signed${signed_err:+ $signed_err}" ;;
        esac
    elif [ -n "$signed_err" ]; then
        echo "$LAUNCHD_LABEL S3 auth: signed check skipped: $signed_err"
    fi

    # Hold the result to what was asked for. `keep` asked for nothing, and an
    # agent still running on the settings it had before this install's plist
    # edit (RESTART_AGENT=0) cannot be expected to follow them yet.
    want=$AGENT_AUTH
    if [ "$pending_reload" = 1 ]; then
        want=keep
        [ "$AGENT_AUTH" = keep ] ||
            echo "note: not checked against AGENT_AUTH=$AGENT_AUTH: the running agent predates its plist"
    fi
    case "$want:$unsigned" in
    *:000 | *:503 | keep:* | enforce:403 | log:2?? | off:2??) ;;
    enforce:2??)
        echo "error: $LAUNCHD_LABEL serves unsigned requests although its plist sets SPICEIO_S3_AUTH=enforce." >&2
        echo "       Something in how it is launched (a wrapper, an env file) overrides it." >&2
        status=1
        ;;
    *:403)
        echo "error: $LAUNCHD_LABEL refuses unsigned requests although its plist sets SPICEIO_S3_AUTH=$AGENT_AUTH." >&2
        status=1
        ;;
    *)
        echo "error: $LAUNCHD_LABEL answered an unsigned ListBuckets with $unsigned; check its log." >&2
        status=1
        ;;
    esac
    if [ "$want" != keep ] && [ -n "$signed" ] && [ "$signed" != 200 ]; then
        echo "error: $LAUNCHD_LABEL does not accept sccache-spiceio's key. sccache-spiceio reads" >&2
        echo "       ${SPICEIO_CLIENT_CREDENTIALS_FILE:-$HOME/.config/spiceio/credentials}; the agent reads ${creds:-its SPICEIO_S3_CREDENTIALS_FILE}." >&2
        status=1
    fi

    # A client in this shell that the agent will now refuse (or, under log,
    # log). Only this shell's settings are visible, but it is the likeliest one
    # to run cargo. sccache run directly signs with a key the agent knows only
    # if one is in AWS_ACCESS_KEY_ID; a profile holds real AWS keys, and
    # SCCACHE_S3_NO_CREDENTIALS sends nothing at all.
    stale_client=0
    if [ "$refused" = 1 ] || [ "$AGENT_AUTH" = log ]; then
        case "${RUSTC_WRAPPER:-}" in
        */sccache | sccache)
            if [ -n "${SCCACHE_S3_NO_CREDENTIALS:-}" ] || [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
                stale_client=1
            fi
            ;;
        esac
    fi
    if [ "$stale_client" = 1 ]; then
        verb="refuses"
        [ "$refused" = 1 ] || verb="logs (and under enforce, refuses)"
        cat <<EOF
note: this shell's sccache does not sign with a key the agent knows
      (RUSTC_WRAPPER=$RUSTC_WRAPPER${SCCACHE_S3_NO_CREDENTIALS:+, SCCACHE_S3_NO_CREDENTIALS=$SCCACHE_S3_NO_CREDENTIALS}), so $LAUNCHD_LABEL $verb
      its requests. In your shell profile:
        export RUSTC_WRAPPER="$wrapper"
        # and remove SCCACHE_S3_NO_CREDENTIALS
      then run \`sccache --stop-server\` once: a running server keeps the settings it started with.
EOF
    fi

    if [ -n "$exposed" ]; then
        if [ "$refused" = 1 ]; then
            cat <<EOF
note: $LAUNCHD_LABEL is reachable from other hosts, and they must sign. Over plain
      HTTP, SigV4 does not encrypt the data, and anyone who captures a request
      can replay it for up to 15 minutes. Keep it on a trusted network.
EOF
        else
            for addr in $exposed; do
                echo "WARNING: $LAUNCHD_LABEL is listening on $addr, reachable from other hosts." >&2
            done
            cat >&2 <<EOF
         Unless it refuses unsigned requests, anyone who can reach that address
         can read, overwrite and delete the whole share. Require SigV4 with
         \`make install\` (AGENT_AUTH=enforce, the default). Or, if the exposure
         is unintended, set SPICEIO_BIND=127.0.0.1:8333 in the agent's
         environment and run \`make install\` again.
EOF
        fi
    fi

    # Each restart is a SIGTERM, then a SIGKILL once the exit timeout runs out.
    # spiceio can need up to 30s to finish in-flight requests and 30s more to
    # flush the write-back backlog.
    exit_timeout=$(agent_field "exit timeout")
    case "$exit_timeout" in
    '' | *[!0-9]*) ;;
    *)
        if [ "$exit_timeout" -lt 60 ]; then
            echo "note: launchd SIGKILLs $LAUNCHD_LABEL ${exit_timeout}s after SIGTERM, which can cut its drain short (up to"
            echo "      60s: in-flight requests, then the write-back backlog). Set ExitTimeOut in its plist to allow for it."
        fi
        ;;
    esac
}

if ! agent_print >/dev/null; then
    echo "note: no launchd agent $LAUNCHD_LABEL is loaded, so there is nothing to restart or set up for SigV4"
    exit 0
fi
agent_plist=$(agent_field path)
[ -n "$agent_plist" ] || die "cannot find the plist $LAUNCHD_LABEL was loaded from ($target)"
creds=""
pending_reload=0

if [ "$AGENT_AUTH" != keep ]; then
    wire_auth "$agent_plist"
fi
# The file the plist resolves to (a symlinked plist is edited at its target).
agent_file=$(realpath "$agent_plist") || die "cannot resolve $agent_plist"
if [ "$AGENT_SMB_PASS" = keychain ]; then
    wire_smb_pass "$agent_file"
elif service=$(keychain_service "$agent_file"); then
    # Told to leave it alone, but still never restart the agent onto a
    # binary that cannot read its password.
    require_readable_smb_pass "$agent_file" "$service"
fi

if loaded_env_is_stale "$agent_plist"; then
    if [ "$RESTART_AGENT" != 0 ]; then
        reload_agent "$agent_plist" || status=$?
    else
        pending_reload=1
        echo "note: $LAUNCHD_LABEL still runs the previous binary and settings. Its plist environment has"
        echo "      changed, which launchd applies only on a reload; \`make install\` reloads it."
    fi
elif [ "$RESTART_AGENT" != 0 ]; then
    echo "restarting $LAUNCHD_LABEL (SIGTERM first, so it can drain)"
    launchctl kickstart -k "$target" || status=$?
else
    echo "note: $LAUNCHD_LABEL still runs the previous binary; restart it with"
    echo "      launchctl kickstart -k $target"
fi

report
exit "$status"
