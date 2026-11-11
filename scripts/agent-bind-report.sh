#!/bin/sh
# Report where a launchd-managed spiceio is listening, and warn loudly when it
# is reachable beyond this host. `make install` runs this after it restarts
# the agent. Reporting only: it never fails the install.
#
#   scripts/agent-bind-report.sh LABEL
#
# The address is read off the running process's listening sockets rather than
# out of the agent's config. That config belongs to the user (a plist, an env
# file it sources, or nothing at all), and only the socket says what actually
# happened. That includes the case this exists for: an agent that never set
# SPICEIO_BIND relied on the old 0.0.0.0 default, and a binary from this tree
# binds loopback only.
#
# `launchctl kickstart -k` returns only once the old process has exited (after
# its drain) and the new one is running, so the pid read here is the new one.
# spiceio binds before it connects to SMB, so the socket shows up quickly; the
# poll only covers process start.
set -u

label="${1:?usage: $0 LABEL}"
target="gui/$(id -u)/$label"

pid=""
addrs=""
tries=50 # x 0.2s
while [ "$tries" -gt 0 ]; do
    pid=$(launchctl print "$target" 2>/dev/null | awk '$1 == "pid" && $2 == "=" { print $3; exit }')
    if [ -n "$pid" ]; then
        # -b/-w: never block on (or warn about) a hung network mount while
        # lsof walks the mount table. lsof prints 0.0.0.0 as `*`.
        addrs=$(lsof -b -w -nP -a -p "$pid" -iTCP -sTCP:LISTEN -Fn 2>/dev/null | sed -n 's/^n//p' | sort -u)
        [ -n "$addrs" ] && break
    fi
    sleep 0.2
    tries=$((tries - 1))
done

if [ -z "$addrs" ]; then
    echo "note: $label is not listening yet (pid ${pid:-none}); check its log"
    exit 0
fi

exposed=""
for addr in $addrs; do
    case "$addr" in
    127.* | '[::1]':*) echo "$label listening on http://$addr (loopback only)" ;;
    *) exposed="$exposed $addr" ;;
    esac
done

if [ -n "$exposed" ]; then
    for addr in $exposed; do
        echo "WARNING: $label is listening on $addr, reachable from other hosts." >&2
    done
    cat >&2 <<EOF
         spiceio does not authenticate S3 requests: anyone who can reach that
         address can read, overwrite and delete the whole share.
         spiceio binds 127.0.0.1:8333 unless SPICEIO_BIND says otherwise. If
         this exposure is not intended, set SPICEIO_BIND=127.0.0.1:8333 in the
         agent's environment and restart it:
           launchctl kickstart -k $target
EOF
fi
exit 0
