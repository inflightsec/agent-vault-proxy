#!/usr/bin/env bash
# Build and sign kow-keyd.
#
# The signature is not decoration — it IS the access control. A keychain item's
# ACL records the designated requirement of the process that created it, so the
# helper's code identity has to be STABLE across rebuilds or every upgrade
# re-prompts. That is the difference between:
#
#   ad-hoc  (codesign -s -)  fresh code hash every build, no team identity
#                            → ACLs invalidated on every rebuild. Never use.
#   self-signed              stable requirement, free, local machine only
#   Developer ID             stable requirement, notarizable, distributable,
#                            and unlocks the data-protection keychain
#
# Apple's TN2206 is explicit that most of macOS cares only that a program is
# validly signed and stable, NOT who issued the certificate. Gatekeeper is the
# exception. So a self-signed certificate is a real answer, not a compromise.
#
#   sh helper/build.sh                      # sign with the local self-signed identity
#   KOW_SIGN_ID="Developer ID Application: … (TEAMID)" sh helper/build.sh
#   KOW_TEAM_ID=ABCDE12345 sh helper/build.sh   # also emit the DP entitlement
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${KOW_KEYD_OUT:-$HERE/kow-keyd}"
IDENTITY="${KOW_SIGN_ID:-kow-keyd local signing}"
TEAM_ID="${KOW_TEAM_ID:-}"

red(){ printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "kow-keyd is macOS-only (got $(uname -s))"; exit 2; }
command -v clang >/dev/null 2>&1 || { red "clang not found — install the Command Line Tools: xcode-select --install"; exit 2; }

echo "==> compiling"
clang -O2 -Wall -Wextra -Werror -o "$OUT" "$HERE/kow-keyd.c" \
      -framework Security -framework CoreFoundation || exit 1

# The entitlement is what the data-protection keychain checks. It is only
# meaningful with a Team ID, so an unsigned or self-signed build simply omits it
# and uses the file-based keychain instead.
#
# THE GROUP MUST STAY kow-SPECIFIC. macOS grants access to EVERY binary signed
# with a matching access group — the group, not the binary, is the unit of
# access. So a bare team group (TEAMID.com.dataminelab) would let every other
# tool signed by the same team read kow's credentials, and one Developer ID
# typically signs several products. Narrow it to this product and keep it
# narrow; "simplifying" this to a shared group silently widens the boundary to
# every binary the team ever ships.
ENTITLEMENTS=""
if [ -n "$TEAM_ID" ]; then
  ENTITLEMENTS="$HERE/kow-keyd.entitlements"
  cat > "$ENTITLEMENTS" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>keychain-access-groups</key>
    <array>
        <string>${TEAM_ID}.com.dataminelab.kow</string>
    </array>
</dict>
</plist>
PLIST
  echo "==> entitlement: ${TEAM_ID}.com.dataminelab.kow"
fi

echo "==> signing as: $IDENTITY"
# No -v: that filters on trust, and trust governs signature VERIFICATION, not
# signing. A self-signed certificate is routinely "invalid" to -v and still
# yields a stable designated requirement, which is the only thing the keychain
# ACL records. Requiring -v breaks every machine without a GUI session.
if ! security find-identity -p codesigning 2>/dev/null | grep -qF "$IDENTITY"; then
  red "no code-signing identity named '$IDENTITY'."
  red "Create a free local one:  sh helper/make-signing-identity.sh"
  red "Or point at yours:        KOW_SIGN_ID='Developer ID Application: … (TEAMID)' sh helper/build.sh"
  exit 1
fi

SIGN_ARGS=(--force --options runtime --identifier com.dataminelab.kow-keyd --sign "$IDENTITY")
[ -n "$ENTITLEMENTS" ] && SIGN_ARGS+=(--entitlements "$ENTITLEMENTS")
codesign "${SIGN_ARGS[@]}" "$OUT" || exit 1

echo "==> designated requirement (this is what the keychain ACL will record):"
codesign -d -r- "$OUT" 2>&1 | sed -n 's/^designated => /    /p'

echo
echo "Built: $OUT"
echo "Stability check — two clean rebuilds must print an IDENTICAL requirement above."
echo "If it changes between builds, every stored secret will re-prompt after an upgrade."
