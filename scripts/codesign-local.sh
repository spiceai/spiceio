#!/bin/sh
# Sign a spiceio binary for `make install`, so a keychain item it stores stays
# readable by every later build.
#
#   scripts/codesign-local.sh SRC DST
#
# Copies SRC to DST and signs DST. Nothing is written to DST unless signing
# succeeds; a failure leaves no DST behind.
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
# their own. The signing keychain asks for its password in this terminal.
# It never shows a dialog: its lock state is checked with
# `spiceio --keychain-status`, which does not prompt, before `codesign` (which
# would) touches it.
#
# Settings (environment):
#   CODESIGN          local (default): sign with the identity in SIGNING_KEYCHAIN,
#                     creating both on first use.
#                     adhoc: ad-hoc signature. A keychain item stored by an
#                     ad-hoc binary is readable by that exact build only.
#   SIGNING_KEYCHAIN  default ~/Library/Keychains/spiceio-signing.keychain-db
#   SPICEIO_STATUS_BIN  a spiceio binary to ask for the keychain's lock state
#                     (default: SRC, which is the build being installed)
#
# First use creates the keychain and a 10-year self-signed code-signing
# certificate (RSA-3072, private key imported non-extractable), then signs.
# It asks for a new password twice, then once more to let codesign use the key.
# Later installs ask for the password once, unless the keychain is already
# unlocked (`security unlock-keychain <path>`); either way it is locked again
# when signing finishes.
set -u

[ $# -eq 2 ] || {
    echo "usage: $0 SRC DST" >&2
    exit 2
}
SRC=$1
DST=$2
CODESIGN="${CODESIGN:-local}"
SIGNING_KEYCHAIN="${SIGNING_KEYCHAIN:-$HOME/Library/Keychains/spiceio-signing.keychain-db}"
SPICEIO_STATUS_BIN="${SPICEIO_STATUS_BIN:-$SRC}"
IDENTIFIER=ai.spice.spiceio
CN="spiceio local code signing"

kc=$SIGNING_KEYCHAIN
work=""
relock=0
signed=0
cleanup() {
    [ -z "$work" ] || rm -rf "$work"
    [ "$relock" = 0 ] || security lock-keychain "$kc" 2>/dev/null
    [ "$signed" = 1 ] || rm -f "$DST"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

die() {
    echo "error: $*" >&2
    exit 1
}

[ -f "$SRC" ] || die "$SRC does not exist"

case "$CODESIGN" in
local | adhoc) ;;
*) die "CODESIGN=$CODESIGN: expected local or adhoc" ;;
esac

# Copy, then sign the copy: SRC (cargo's output) is left as built.
stage() {
    rm -f "$DST"
    cp "$SRC" "$DST" && chmod 0755 "$DST" || die "cannot write $DST"
    # Drop the linker's ad-hoc signature first, so codesign signs a clean
    # binary instead of announcing that it is replacing one.
    codesign --remove-signature "$DST" 2>/dev/null || true
}

if [ "$CODESIGN" = adhoc ]; then
    stage
    codesign -f -s - -i "$IDENTIFIER" -o runtime "$DST" || die "codesign failed"
    signed=1
    echo "signed $DST ad-hoc (a keychain item it stores is readable by this build only)"
    exit 0
fi

case "$kc" in
/*) ;;
*) die "SIGNING_KEYCHAIN=$kc is not an absolute path" ;;
esac

keychain_state() { "$SPICEIO_STATUS_BIN" --keychain-status "$kc"; }

# The SHA-1 of the signing identity in the keychain, if it has one. Run only
# once the keychain is unlocked.
identity_hash() {
    security find-identity -p codesigning "$kc" 2>/dev/null |
        awk -v cn="\"$CN\"" '/Matching identities/ { m = 1 } m && index($0, cn) { print $2; exit }'
}

create_identity() {
    [ -t 0 ] || die "there is no signing keychain at $kc yet, and creating one asks you to
       choose its password. Run \`make install\` in a terminal once."
    cat <<EOF
make install signs spiceio with a local, self-signed certificate so the keychain
item holding the SMB password stays readable by every build you install.
Creating its own keychain for the signing key: $kc
Choose a password for it (not your login password). install asks for it each
time it signs, so nothing else running as you can sign with this key.
EOF
    dir=$(dirname "$kc")
    [ -d "$dir" ] || (umask 077 && mkdir -p "$dir") || die "cannot create $dir"
    security create-keychain "$kc" || die "could not create $kc"
    chmod 600 "$kc"
    relock=1
    # Lock on sleep and after five idle minutes, in case a signing run is
    # interrupted before it locks the keychain itself.
    security set-keychain-settings -l -u -t 300 "$kc" || die "could not configure $kc"

    work=$(mktemp -d "${TMPDIR:-/tmp}/spiceio-sign.XXXXXX") || die "mktemp failed"
    chmod 700 "$work"
    cat >"$work/req.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
CN = $CN
[ext]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
EOF
    # /usr/bin/openssl (LibreSSL, part of macOS): its PKCS#12 defaults are the
    # ones `security import` reads. The key file exists only in this 0700
    # directory, for the second it takes to import it.
    /usr/bin/openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
        -config "$work/req.cnf" -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null ||
        die "openssl could not create the certificate"
    p12pass=$(/usr/bin/openssl rand -hex 16) || die "openssl rand failed"
    P12PASS=$p12pass /usr/bin/openssl pkcs12 -export -name "$CN" \
        -inkey "$work/key.pem" -in "$work/cert.pem" -out "$work/id.p12" -passout env:P12PASS ||
        die "openssl could not package the identity"
    # -x: the private key can never be exported again. -T: codesign may use it
    # (while this keychain is unlocked) without a dialog.
    security import "$work/id.p12" -k "$kc" -f pkcs12 -P "$p12pass" -x -T /usr/bin/codesign >/dev/null ||
        die "could not import the identity into $kc"
    rm -rf "$work"
    work=""
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
         security unlock-keychain '$kc'
       (install locks it again when it is done)."
        security unlock-keychain "$kc" || die "could not unlock $kc"
        ;;
    *) die "unexpected keychain state \"$state\" for $kc" ;;
    esac
    relock=1
fi

hash=$(identity_hash)
[ -n "$hash" ] || die "$kc has no \"$CN\" identity. To start over, delete the keychain
       (security delete-keychain '$kc') and run \`make install\` again. A new identity
       cannot read keychain items the old one stored: store the SMB password again."

stage
# --timestamp=none: nothing to ask Apple's timestamp server about a
# self-signed signature. -o runtime: the hardened runtime, so no other
# process running as you can attach to spiceio or inject a library into it to
# read the password from its memory.
codesign -f -s "$hash" --keychain "$kc" -i "$IDENTIFIER" -o runtime --timestamp=none "$DST" ||
    die "codesign failed"
codesign --verify --strict "$DST" || die "the signature on $DST does not verify"
signed=1
requirement=$(codesign -d -r- "$DST" 2>&1 | sed -n 's/^designated => //p')
echo "signed $DST: $requirement"
