# Keychain helpers shared by scripts/test-agent-install.sh and
# scripts/test-codesign-local.sh (bash; sourced, not run).

# signing KC CMD...: run CMD (codesign, or a function that runs it) as
# codesign-local.sh does: with HOME a private directory whose keychain search
# list holds KC alone (codesign finds a --keychain identity only through the
# list in some sessions, such as the CI runner's). The user's own search list
# is never edited.
signing() {
    local kc=$1 home rc=0
    shift
    home=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-sign.XXXXXX")
    mkdir -p "$home/Library/Preferences"
    HOME=$home security list-keychains -d user -s "$kc"
    HOME=$home "$@" || rc=$?
    rm -f "$home/Library/Preferences/com.apple.security.plist"
    rmdir "$home/Library/Preferences" "$home/Library" "$home"
    return $rc
}
# search_list_kept BEFORE DIR: the user's keychain search list still holds
# every entry of BEFORE (what it printed when the run began), and no keychain
# under DIR. Entries another process adds meanwhile do not fail it: the CI
# runner is shared, and a list compared whole failed a run for a change this
# one never made. Sets OUT to both lists, so a failing check shows them.
search_list_kept() {
    local now line
    now=$(security list-keychains -d user)
    OUT=$(printf 'before:\n%s\nnow:\n%s' "$1" "$now")
    while IFS= read -r line; do
        [[ -z "$line" ]] || grep -qxF -- "$line" <<<"$now" || return 1
    done <<<"$1"
    ! grep -qF -- "$2" <<<"$now"
}
# signing_diagnostics KC: what to look at when signing with KC fails.
signing_diagnostics() {
    {
        echo "macOS $(sw_vers -productVersion), session $(launchctl managername 2>/dev/null)"
        echo "identities in $1:"
        security find-identity -p codesigning "$1"
        echo "valid identities in $1:"
        security find-identity -v -p codesigning "$1"
    } >&2
}
