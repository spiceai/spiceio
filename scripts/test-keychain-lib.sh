# Keychain helpers shared by scripts/test-agent-install.sh and
# scripts/test-codesign-local.sh (bash; sourced, not run).

# listed KC CMD...: run CMD with keychain KC on the user's search list, as
# codesign-local.sh does while it signs (codesign finds a --keychain identity
# only through the list in some sessions, such as the CI runner's). The list
# is re-read before taking KC off again, so other changes survive.
listed() {
    local kc=$1 rc=0 k
    shift
    local list=()
    while IFS= read -r k; do
        k=${k#*\"}
        k=${k%\"*}
        [[ -n "$k" ]] && list+=("$k")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "${list[@]}" "$kc"
    "$@" || rc=$?
    unlist "$kc"
    return $rc
}
# unlist KC: take KC off the user's search list, in either spelling
# (`security list-keychains` prints /private/var/… for /var/…).
unlist() {
    local kc=$1 real k
    real=$(cd "$(dirname "$kc")" 2>/dev/null && pwd -P)/$(basename "$kc")
    local list=()
    while IFS= read -r k; do
        k=${k#*\"}
        k=${k%\"*}
        [[ -n "$k" && "$k" != "$kc" && "$k" != "$real" ]] && list+=("$k")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "${list[@]}"
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
