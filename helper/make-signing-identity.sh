#!/usr/bin/env bash
# Create a free, local, self-signed code-signing identity for kow-keyd.
#
# You do NOT need an Apple Developer Program membership for the keychain ACL to
# stick. Apple's TN2206 says most of macOS cares only that a program is validly
# signed and STABLE — stability being determined by the designated requirement —
# "independent of the nature of the certificate authority used". Gatekeeper is
# the exception, which is why a self-signed build is for your own machine and a
# Developer ID is what you need to ship binaries to other people.
#
# What this touches on your machine, stated plainly: it adds one certificate and
# its private key to your LOGIN keychain, and marks that certificate trusted for
# code signing in your USER trust domain. No sudo, nothing system-wide, and it
# is reversible — see the teardown line at the end.
#
#   sh helper/make-signing-identity.sh
#   sh helper/make-signing-identity.sh --remove
set -uo pipefail

CN="${KOW_SIGN_ID:-kow-keyd local signing}"
KEYCHAIN="${KOW_SIGN_KEYCHAIN:-$HOME/Library/Keychains/login.keychain-db}"

red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green(){ printf '\033[1;32m%s\033[0m\n' "$*"; }

[ "$(uname -s)" = "Darwin" ] || { red "macOS only (got $(uname -s))"; exit 2; }

if [ "${1:-}" = "--remove" ]; then
  echo "==> removing '$CN' from $KEYCHAIN"
  security delete-identity -c "$CN" "$KEYCHAIN" >/dev/null 2>&1 \
    && green "removed" || echo "nothing to remove"
  exit 0
fi

if security find-identity -v -p codesigning "$KEYCHAIN" 2>/dev/null | grep -qF "$CN"; then
  green "identity '$CN' already exists — nothing to do"
  echo "Reuse it. Regenerating would change the designated requirement and"
  echo "invalidate the ACL on every secret already stored."
  exit 0
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/kow-signid.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

echo "==> generating a self-signed code-signing certificate"
# extendedKeyUsage=codeSigning is the part that makes codesign accept it; without
# it the certificate imports fine and is then invisible to `find-identity`.
cat > "$WORK/openssl.cnf" <<'CNF'
[ req ]
distinguished_name = dn
x509_extensions    = ext
prompt             = no
[ dn ]
CN = PLACEHOLDER_CN
[ ext ]
basicConstraints       = critical,CA:false
keyUsage               = critical,digitalSignature
extendedKeyUsage       = critical,codeSigning
subjectKeyIdentifier   = hash
CNF
sed -i '' "s/PLACEHOLDER_CN/$CN/" "$WORK/openssl.cnf"

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -config "$WORK/openssl.cnf" 2>/dev/null || { red "openssl failed"; exit 1; }

# -legacy: the macOS keychain reads the older PKCS#12 encryption. Without it the
# import "succeeds" and the identity is unusable for signing — a silent failure
# that costs an hour to diagnose.
openssl pkcs12 -export -legacy -out "$WORK/id.p12" \
    -inkey "$WORK/key.pem" -in "$WORK/cert.pem" -passout pass:kow 2>/dev/null \
  || openssl pkcs12 -export -out "$WORK/id.p12" \
       -inkey "$WORK/key.pem" -in "$WORK/cert.pem" -passout pass:kow 2>/dev/null \
  || { red "pkcs12 export failed"; exit 1; }

echo "==> importing into $KEYCHAIN (grants /usr/bin/codesign use of the key)"
security import "$WORK/id.p12" -k "$KEYCHAIN" -P kow \
    -T /usr/bin/codesign -T /usr/bin/security >/dev/null || { red "import failed"; exit 1; }

echo "==> trusting it for code signing (user trust domain, no sudo)"
# No -d: this is the USER trust domain. -d would be the admin/system domain and
# would need sudo, which this has no business asking for.
security add-trusted-cert -r trustRoot -p codeSign -k "$KEYCHAIN" "$WORK/cert.pem" >/dev/null 2>&1 \
  || echo "note: add-trusted-cert reported a problem; checking whether signing works anyway"

# Stop codesign from prompting for access to the private key on every build.
# The partition list is the 10.12.5+ mechanism that sits alongside the ACL; get
# it wrong and signing works interactively but hangs in CI waiting on a dialog.
# KOW_SIGN_KEYCHAIN_PW is only needed for a non-login keychain (CI, tests).
security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
    -k "${KOW_SIGN_KEYCHAIN_PW:-}" "$KEYCHAIN" >/dev/null 2>&1 || true

# Verify by SIGNING something, not by asking whether the certificate is trusted.
#
# `find-identity -v` filters on trust, and trust is not what matters here.
# Trust settings govern signature *verification* (and Gatekeeper); signing needs
# only a private key with the code-signing usage. A self-signed certificate that
# `-v` calls invalid will still produce a perfectly stable designated
# requirement, which is the only property the keychain ACL cares about. Gating
# on `-v` fails on any machine without a GUI session to authorise the trust
# change — CI runners and SSH sessions included.
PROBE="$(mktemp -d "${TMPDIR:-/tmp}/kow-signprobe.XXXXXX")"
printf 'int main(void){return 0;}\n' > "$PROBE/p.c"
if clang -o "$PROBE/p" "$PROBE/p.c" 2>/dev/null \
   && codesign --force --identifier com.dataminelab.kow-signprobe --sign "$CN" "$PROBE/p" 2>/dev/null; then
  REQ=$(codesign -d -r- "$PROBE/p" 2>&1 | sed -n 's/^designated => //p')
  rm -rf "$PROBE"
  case "$REQ" in
    ""|*adhoc*)
      red "signing produced no stable requirement (got: ${REQ:-none})"
      exit 1 ;;
  esac
  green "identity ready: $CN"
  echo "    designated requirement: $REQ"
  echo
  echo "Next:    sh helper/build.sh"
  echo "Undo:    sh helper/make-signing-identity.sh --remove"
  echo
  echo "Keep this certificate. Its designated requirement is what the keychain"
  echo "ACL records; regenerating it orphans every secret already stored."
else
  rm -rf "$PROBE"
  red "the identity exists but codesign could not use it."
  red "In Keychain Access, find '$CN' and set 'Code Signing' trust to 'Always Trust'."
  exit 1
fi
