#!/bin/sh
# Sign a spiceio binary for `make install`, so a keychain item it stores stays
# readable by every later build.
#
#   scripts/codesign-local.sh SRC DST
#
# Signs a copy of SRC and renames it over DST only once its signature
# verifies. The copy is a temp file beside DST; a failure at any point
# removes only that file, so an existing DST (an installed binary, say) is
# never deleted or left half-written.
#
# Why: a keychain item's access list names the designated requirement of the
# binary that created it. cargo signs ad-hoc, so that requirement is the
# binary's cdhash and every rebuild is a stranger to the keychain. Signed with
# a certificate, the requirement is `identifier "ai.spice.spiceio" and
# certificate leaf = H"…"`, which every build signed with the same certificate
# satisfies. The certificate is self-signed: no Apple Developer account is
# involved, and macOS does not need to trust it for the keychain check.
#
# Where the key lives: in its own keychain (SIGNING_KEYCHAIN), with its own
# password, locked except while this script signs. Anything signed with this
# key can read the SMB password, so the key must not be usable by whatever
# else runs as you. A key in the login keychain that `codesign` may use
# without asking could be used by any of those processes to sign a binary of
# their own. The key pair is generated *inside* that keychain by `spiceio
# --create-signing-identity`, non-extractable from birth, and spiceio signs
# the self-signed certificate itself: the private key is never in a file, so
# no copy of it can exist. The signing keychain asks for its password in this
# terminal. It never shows a dialog: its lock state is checked with `spiceio
# --keychain-status`, which does not prompt, before `codesign` (which would)
# touches it.
#
# Settings (environment):
#   CODESIGN          local (default): sign with the identity in SIGNING_KEYCHAIN,
#                     creating both on first use.
#                     adhoc: ad-hoc signature. A keychain item stored by an
#                     ad-hoc binary is readable by that exact build only.
#   SIGNING_KEYCHAIN  default ~/Library/Keychains/spiceio-signing.keychain-db
#   SPICEIO_HELPER_BIN  the spiceio binary that checks the keychain's lock state
#                     and creates the identity (default: SRC, the build being
#                     installed)
#
# First use creates the keychain and a 10-year self-signed code-signing
# identity (RSA-3072), then signs. It asks for a new password twice, then once
# more to let codesign use the key. Later installs ask for the password once,
# unless the keychain is already unlocked (`security unlock-keychain <path>`);
# either way it is locked again when signing finishes.
set -u

[ $# -eq 2 ] || {
    echo "usage: $0 SRC DST" >&2
    exit 2
}
SRC=$1
DST=$2
CODESIGN="${CODESIGN:-local}"
SIGNING_KEYCHAIN="${SIGNING_KEYCHAIN:-$HOME/Library/Keychains/spiceio-signing.keychain-db}"
SPICEIO_HELPER_BIN="${SPICEIO_HELPER_BIN:-$SRC}"
IDENTIFIER=ai.spice.spiceio
CN="spiceio local code signing"

kc=$SIGNING_KEYCHAIN
staged=""
relock=0
signed=0
created=0
sign_home=""
cleanup() {
    [ -z "$staged" ] || rm -f "$staged"
    drop_sign_home
    [ "$relock" = 0 ] || security lock-keychain "$kc" 2>/dev/null
    # A keychain this run created but could not finish (an exportable key,
    # say) must not be picked up by the next install as a working one.
    [ "$created" = 0 ] || [ "$signed" = 1 ] || security delete-keychain "$kc" 2>/dev/null
}

# codesign finds a `--keychain` identity only through the keychain search
# list in some sessions: on a CI runner it answered "no identity found" for
# a keychain named with --keychain but not on the list, where a login session
# signs fine. The user's own list is never edited for it, not even briefly:
# other processes running as the user would see the signing keychain come and
# go (a test that compares the list before and after, another install). codesign
# runs with HOME set to a private directory instead. Security keeps the search
# list in $HOME/Library/Preferences/com.apple.security.plist, so that
# directory's list holds the signing keychain alone and the user's list never
# changes (measured: under an empty private HOME the list reads empty, setting
# it writes only the private file, and codesign then signs).
make_sign_home() {
    sign_home=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-sign.XXXXXX") || die "cannot create a private keychain search list"
    mkdir "$sign_home/Library" "$sign_home/Library/Preferences" || die "cannot create a private keychain search list"
    # If Security ignored HOME, setting the list below would replace the
    # user's own. An empty private HOME must read an empty list first.
    [ -z "$(HOME=$sign_home security list-keychains -d user)" ] ||
        die "security does not read the keychain search list from HOME here; not signing (it would edit your search list)"
    HOME=$sign_home security list-keychains -d user -s "$kc" || die "cannot set a private keychain search list"
    # Compared as files, not strings: security prints the resolved path, and
    # SIGNING_KEYCHAIN may name the keychain through a symlink.
    listed=$(HOME=$sign_home security list-keychains -d user | sed 's/^[[:space:]]*"//; s/"$//')
    [ -e "$listed" ] && [ "$(stat -L -f %d:%i "$listed")" = "$(stat -L -f %d:%i "$kc")" ] ||
        die "the private keychain search list does not hold $kc"
}
drop_sign_home() {
    [ -n "$sign_home" ] || return 0
    rm -f "$sign_home/Library/Preferences/com.apple.security.plist"
    rmdir "$sign_home/Library/Preferences" "$sign_home/Library" "$sign_home" 2>/dev/null
    sign_home=""
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() {
    echo "error: $*" >&2
    exit 1
}

# $1 single-quoted, for a command printed as a suggestion: a path holding a
# quote must not turn a pasted command into one on another keychain.
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

[ -f "$SRC" ] || die "$SRC does not exist"

case "$CODESIGN" in
local | adhoc) ;;
*) die "CODESIGN=$CODESIGN: expected local or adhoc" ;;
esac

# Copy SRC (cargo's output, left as built) to a temp file beside DST, so the
# final rename is atomic and nothing but that temp file is ever removed.
stage() {
    staged=$(mktemp "$(dirname "$DST")/.$(basename "$DST").XXXXXX") || die "cannot write beside $DST"
    cp "$SRC" "$staged" && chmod 0755 "$staged" || die "cannot write $staged"
    # Drop the linker's ad-hoc signature first, so codesign signs a clean
    # binary instead of announcing that it is replacing one.
    codesign --remove-signature "$staged" 2>/dev/null || true
}

# Put the verified copy in place.
publish() {
    mv -f "$staged" "$DST" || die "cannot replace $DST"
    staged=""
    signed=1
}

if [ "$CODESIGN" = adhoc ]; then
    stage
    codesign -f -s - -i "$IDENTIFIER" -o runtime "$staged" || die "codesign failed"
    publish
    echo "signed $DST ad-hoc (a keychain item it stores is readable by this build only)"
    exit 0
fi

case "$kc" in
/*) ;;
*) die "SIGNING_KEYCHAIN=$kc is not an absolute path" ;;
esac

# One install at a time for this user (scripts/install-lock.sh): each run
# unlocks the keychain (or finds it unlocked), signs and locks it again, and
# two concurrent runs would lock it under each other's codesign. `make
# install` already holds the lock; run on its own, the script takes it.
[ -n "${SPICEIO_INSTALL_LOCK_HELD:-}" ] ||
    exec /bin/sh "$(dirname "$0")/install-lock.sh" /bin/sh "$0" "$@"

keychain_state() { "$SPICEIO_HELPER_BIN" --keychain-status "$kc"; }

# The SHA-1 of the signing identity in the keychain, if it has one. Run only
# once the keychain is unlocked.
identity_hash() {
    security find-identity -p codesigning "$kc" 2>/dev/null |
        awk -v cn="\"$CN\"" '/Matching identities/ { m = 1 } m && index($0, cn) { print $2 }'
}

# The value of attribute $1 of the signing keychain's private key, as
# `security dump-keychain` prints it (attributes only: no -d, so no ACL check
# and no dialog).
key_attribute() {
    security dump-keychain "$kc" 2>/dev/null |
        awk -v a="$1" '/^keychain:/ { k = 0 } /^class: 0x00000010/ { k = 1 } k && $1 == a { print $2 }'
}

# Refuse a signing keychain holding a key that can be exported, on every
# run: a key made outside this script, by hand or by a version that imported
# a .p12 (whose -x `security import -f pkcs12` ignores), may be exportable,
# and a copy of it could sign a binary that reads the SMB password. Every
# private key in the keychain is checked, not just one: which one signs is
# the identity's, and the keychain holds only that one (see the identity
# check). Reading the Extractable attribute (0x10) touches no ACL, so it
# raises no dialog.
require_unexportable_key() {
    keys=$(key_attribute 0x00000010)
    extractable=$(printf '%s\n' "$keys" | grep -v -x '<uint32>=0x00000000' | head -1)
    [ -n "$keys" ] && [ -z "$extractable" ] && return 0
    die "a signing key in $kc is exportable (Extractable ${extractable:-unknown}), so a copy of it
       could sign a binary that reads the SMB password. Not signing with it. To start over,
       delete the keychain (security delete-keychain $(shq "$kc")) and run \`make install\`
       again; a new identity cannot read items the old one stored (README, \"New signing identity\")."
}

create_identity() {
    [ -t 0 ] || die "there is no signing keychain at $kc yet, and creating one asks you to
       choose its password. Run \`make install\` in a terminal once."
    cat <<EOF
make install signs spiceio with a local, self-signed certificate so the keychain
item holding the SMB password stays readable by every build you install.
Creating its own keychain for the signing key: $kc
Choose a password for it (not your login password). install asks for it each
time it signs and locks the keychain again afterwards, so the key is usable
only while install is signing.
EOF
    dir=$(dirname "$kc")
    [ -d "$dir" ] || (umask 077 && mkdir -p "$dir") || die "cannot create $dir"
    security create-keychain "$kc" || die "could not create $kc"
    created=1
    chmod 600 "$kc"
    relock=1
    # Lock on sleep and after five idle minutes, in case a signing run is
    # interrupted before it locks the keychain itself.
    security set-keychain-settings -l -u -t 300 "$kc" || die "could not configure $kc"
    # Key pair generated in the keychain, certificate signed by spiceio: the
    # private key is never written to a file. codesign is on its access list.
    "$SPICEIO_HELPER_BIN" --create-signing-identity "$kc" "$CN" >/dev/null ||
        die "could not create the signing identity in $kc"
    # Check it rather than trust the flag, before codesign is let near it.
    require_unexportable_key
    echo "Allow codesign to use the new key (asks for the signing keychain's password again):"
    security set-key-partition-list -S apple-tool:,apple: -s "$kc" >/dev/null ||
        die "could not let codesign use the key in $kc"
}

if [ ! -e "$kc" ]; then
    create_identity
else
    state=$(keychain_state) || die "cannot tell whether $kc is locked"
    case "$state" in
    unlocked) ;;
    locked)
        [ -t 0 ] || die "the signing keychain is locked, and there is no terminal to ask for its
       password. Run \`make install\` in a terminal, or unlock it first:
         security unlock-keychain $(shq "$kc")
       (install locks it again when it is done)."
        security unlock-keychain "$kc" || die "could not unlock $kc"
        ;;
    *) die "unexpected keychain state \"$state\" for $kc" ;;
    esac
    relock=1
fi

hashes=$(identity_hash)
hash=$(printf '%s\n' "$hashes" | head -1)
# Exactly one: with two of the same name, which one codesign is handed
# depends on the order security lists them.
[ "$(printf '%s\n' "$hashes" | grep -c .)" -le 1 ] ||
    die "$kc holds $(printf '%s\n' "$hashes" | grep -c .) \"$CN\" identities; expected one.
       Remove the extra ones, or start over (security delete-keychain $(shq "$kc"))."
[ -n "$hash" ] || die "$kc has no \"$CN\" identity. To start over, delete the keychain
       (security delete-keychain $(shq "$kc")) and run \`make install\` again. A new identity
       cannot read keychain items the old one stored: see README, \"New signing identity\"."
require_unexportable_key

stage
# --timestamp=none: nothing to ask Apple's timestamp server about a
# self-signed signature. -o runtime: the hardened runtime, so no other
# process running as you can attach to spiceio or inject a library into it to
# read the password from its memory.
make_sign_home
HOME=$sign_home codesign -f -s "$hash" --keychain "$kc" -i "$IDENTIFIER" -o runtime --timestamp=none "$staged" ||
    die "codesign failed"
drop_sign_home
codesign --verify --strict "$staged" || die "the signature on $staged does not verify"
publish
requirement=$(codesign -d -r- "$DST" 2>&1 | sed -n 's/^designated => //p')
echo "signed $DST: $requirement"
