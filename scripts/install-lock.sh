#!/bin/sh
# Run a command holding this user's spiceio install lock:
#
#   scripts/install-lock.sh CMD [ARG...]
#
# `make install` holds it for the whole install, and codesign-local.sh and
# agent-install.sh take it when run on their own, so two installs never
# interleave. Without it, two concurrent installs could:
#   - lock the signing keychain under each other's codesign, which then fails
#     or, in a login session, asks for the password in a dialog;
#   - edit the agent's plist, move its SMB password and restart it at the same
#     time, and leave it with neither a password nor a keychain item to read.
# A second install waits (up to 15 minutes) and says so.
#
# The lock is one file per user, in `getconf DARWIN_USER_TEMP_DIR`, which
# does not follow TMPDIR or HOME. It is not named after a keychain or a
# plist, because two paths to one file (a symlink) would then take different
# locks. A command run with the lock already held by its caller
# (SPICEIO_INSTALL_LOCK_HELD) runs directly: lockf(1) on a file the caller
# has locked would wait for the caller, which is waiting for it.
set -u

[ $# -gt 0 ] || {
    echo "usage: $0 CMD [ARG...]" >&2
    exit 2
}
user_tmp=$(getconf DARWIN_USER_TEMP_DIR) && [ -n "$user_tmp" ] || {
    echo "error: cannot find this user's temporary directory for the install lock" >&2
    exit 1
}
lock="${user_tmp%/}/spiceio-install.lock"
[ "${SPICEIO_INSTALL_LOCK_HELD:-}" != "$lock" ] || exec "$@"
lockf -k -s -t 0 "$lock" true || echo "waiting for another spiceio install to finish" >&2
SPICEIO_INSTALL_LOCK_HELD=$lock
export SPICEIO_INSTALL_LOCK_HELD
exec lockf -k -t 900 "$lock" "$@"
