#!/usr/bin/env bash
# kow-keyd end-to-end: does the signed helper actually scope keychain access?
#
# Runs on ANY Mac — a contributor's laptop, a GitHub runner, a VM. Everything
# happens in a throwaway keychain with a throwaway signing identity, and both
# are removed on exit. Your login keychain is never touched.
#
#   bash tests/vm-e2e/macos-keyd-e2e.sh
#   bash tests/vm-e2e/macos-keyd-e2e.sh --keep     # leave it for inspection
#
# THE ASSERTION THAT MATTERS
#
# Everything else here is scaffolding for one question: with an item created by
# the signed helper, can a process that is NOT the helper read it? Specifically
# a Python script — because kow ships through PyPI, so if "grant access to kow"
# means "grant access to the interpreter", then any script an agent writes
# inherits the credential and the whole exercise is theatre.
#
# So the leg proves, in order:
#   1. the helper reads its own item silently          (no prompt, exit 0)
#   2. /usr/bin/security CANNOT read it                (not in the ACL)
#   3. a Python script CANNOT read it                  (this is the point)
#   4. a REBUILT helper still reads it                 (stable requirement)
set -uo pipefail

KEEP=0
for a in "$@"; do
  case "$a" in
    --keep) KEEP=1 ;;
    -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n== %s\n' "$*"; }
red()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "macOS only (got $(uname -s))"; exit 2; }
[ "$(id -u)" -ne 0 ] || { red "must not run as root — a keychain belongs to a login session"; exit 2; }
command -v clang >/dev/null 2>&1 || { red "clang not found: xcode-select --install"; exit 2; }

SRC="${KOW_SRC:-$(cd "$(dirname "$0")/../.." && pwd)}"
[ -f "$SRC/helper/kow-keyd.c" ] || { red "no kow-keyd source at $SRC/helper"; exit 2; }

SERVICE="kow-keyd-e2e"
ACCOUNT="MACTEST_KEY"
SECRET="sk-live-KEYD-$(head -c8 /dev/urandom | xxd -p)"
CN="kow-keyd e2e $$"

BASE="$(mktemp -d "${TMPDIR:-/tmp}/kow-keyd-e2e.XXXXXX")"
KEYCHAIN="$BASE/keyd-e2e.keychain-db"
SIGNKC="$BASE/keyd-signing.keychain-db"
KCPW="e2e-$(head -c12 /dev/urandom | xxd -p)"
# Saved so the search list can be put back exactly as it was. A leaked entry
# here outlives the files and confuses every later `security` call.
ORIG_LIST=$(security list-keychains -d user | tr -d ' "')

cleanup() {
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s\n' "$BASE"; return; fi
  # shellcheck disable=SC2086 — the saved list is intentionally word-split
  [ -n "$ORIG_LIST" ] && security list-keychains -d user -s $ORIG_LIST 2>/dev/null
  security delete-keychain "$KEYCHAIN" 2>/dev/null
  security delete-keychain "$SIGNKC" 2>/dev/null
  rm -rf "$BASE"
  local left=""
  [ -e "$KEYCHAIN" ] && left="$left keychain"
  [ -e "$SIGNKC" ] && left="$left signing-keychain"
  security find-identity -v -p codesigning 2>/dev/null | grep -qF "$CN" && left="$left identity"
  security list-keychains -d user | grep -q keyd-signing && left="$left search-list-entry"
  [ -z "$left" ] && printf '  clean: keychains, identity and search list restored\n' || red "  RESIDUE LEFT:$left"
}
trap cleanup EXIT

printf 'src=%s  keychain=%s\n' "$SRC" "$KEYCHAIN"

# ------------------------------------------------------------------ identity

step "1. a throwaway self-signed code-signing identity"
# NOT the login keychain: over SSH (and on a CI runner) there is no GUI session,
# so the login keychain is locked and `security import` fails with "User
# interaction is not allowed". A dedicated keychain we create and unlock
# ourselves has no such problem — and leaves the user's login keychain alone,
# which is the right behaviour for a test regardless.
security create-keychain -p "$KCPW" "$SIGNKC" || { bad "could not create the signing keychain"; exit 1; }
security set-keychain-settings "$SIGNKC"
security unlock-keychain -p "$KCPW" "$SIGNKC" || { bad "could not unlock the signing keychain"; exit 1; }
# codesign resolves identities through the SEARCH LIST, so the new keychain has
# to join it or `find-identity` will not see the certificate at all.
# shellcheck disable=SC2086
security list-keychains -d user -s $ORIG_LIST "$SIGNKC" || { bad "could not extend the search list"; exit 1; }

if KOW_SIGN_ID="$CN" KOW_SIGN_KEYCHAIN="$SIGNKC" KOW_SIGN_KEYCHAIN_PW="$KCPW" \
     bash "$SRC/helper/make-signing-identity.sh" >"$BASE/identity.log" 2>&1; then
  ok "created identity '$CN' in a throwaway keychain"
else
  bad "could not create a signing identity"; tail -20 "$BASE/identity.log"; exit 1
fi

step "2. build + sign kow-keyd"
if KOW_SIGN_ID="$CN" KOW_KEYD_OUT="$BASE/kow-keyd" \
     bash "$SRC/helper/build.sh" >"$BASE/build.log" 2>&1; then
  ok "compiled and signed"
else
  bad "build failed"; tail -20 "$BASE/build.log"; exit 1
fi
KEYD="$BASE/kow-keyd"

DR1=$(codesign -d -r- "$KEYD" 2>&1 | sed -n 's/^designated => //p')
[ -n "$DR1" ] && ok "designated requirement present" || bad "no designated requirement"
case "$DR1" in
  *adhoc*) bad "signature is ad-hoc — the ACL would break on every rebuild" ;;
  *)       ok "not ad-hoc (requirement is stable across rebuilds)" ;;
esac

# ------------------------------------------------------------------ keychain

step "3. throwaway keychain"
security create-keychain -p "$KCPW" "$KEYCHAIN" && ok "created" || { bad "create-keychain"; exit 1; }
security set-keychain-settings "$KEYCHAIN"
security unlock-keychain -p "$KCPW" "$KEYCHAIN" && ok "unlocked" || bad "unlock failed"

step "4. the helper writes (value on stdin, never argv)"
if printf '%s' "$SECRET" | "$KEYD" set --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" 2>"$BASE/set.err"; then
  ok "kow-keyd set"
else
  bad "kow-keyd set failed (rc $?)"; cat "$BASE/set.err"
fi

step "5. the helper reads its own item, with no prompt"
GOT=$("$KEYD" get --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" 2>"$BASE/get.err"); RC=$?
if [ "$RC" != 0 ]; then
  bad "kow-keyd get failed (rc $RC)"; cat "$BASE/get.err"
elif [ "$GOT" = "$SECRET" ]; then
  ok "read back byte-identical, exit 0, no interaction"
else
  bad "value mismatch (${#GOT} bytes back, ${#SECRET} written)"
fi

step "6. enumeration"
"$KEYD" list --service "$SERVICE" --keychain "$KEYCHAIN" 2>/dev/null | grep -qx "$ACCOUNT" \
  && ok "kow-keyd list shows $ACCOUNT" || bad "list did not show the account"

# ============================================================ THE REAL TEST
#
# From here down is the whole reason the helper exists.

step "7. /usr/bin/security must NOT be able to read it"
SEC_OUT=$(security find-generic-password -s "$SERVICE" -a "$ACCOUNT" -w "$KEYCHAIN" 2>&1); SEC_RC=$?
if [ "$SEC_RC" = 0 ] && [ "$SEC_OUT" = "$SECRET" ]; then
  bad "security(1) READ THE SECRET — the ACL is not scoped"
elif [ "$SEC_RC" = 0 ]; then
  bad "security(1) exited 0 unexpectedly"
else
  ok "security(1) refused (rc $SEC_RC)"
fi

step "8. a Python script must NOT be able to read it — THE POINT"
# kow ships through PyPI, so if the grant landed on the interpreter rather than
# on the helper, this is the script an agent writes to walk straight past it.
cat > "$BASE/steal.py" <<'PY'
import ctypes, ctypes.util, sys

# The same call the helper makes, from an unsigned interpreter.
Sec = ctypes.CDLL(ctypes.util.find_library("Security"))
CF = ctypes.CDLL(ctypes.util.find_library("CoreFoundation"))
service, account, keychain = sys.argv[1], sys.argv[2], sys.argv[3]

Sec.SecKeychainOpen.restype = ctypes.c_int32
kc = ctypes.c_void_p()
if Sec.SecKeychainOpen(keychain.encode(), ctypes.byref(kc)) != 0:
    print("OPEN_FAILED"); sys.exit(3)

length = ctypes.c_uint32()
data = ctypes.c_void_p()
Sec.SecKeychainFindGenericPassword.restype = ctypes.c_int32
st = Sec.SecKeychainFindGenericPassword(
    kc,
    ctypes.c_uint32(len(service)), service.encode(),
    ctypes.c_uint32(len(account)), account.encode(),
    ctypes.byref(length), ctypes.byref(data), None)
if st == 0:
    print("STOLE:" + ctypes.string_at(data.value, length.value).decode())
    sys.exit(0)
print("DENIED:%d" % st)
sys.exit(1)
PY
PY_BIN="$(command -v python3)"
PY_OUT=$("$PY_BIN" "$BASE/steal.py" "$SERVICE" "$ACCOUNT" "$KEYCHAIN" 2>&1); PY_RC=$?
case "$PY_OUT" in
  STOLE:*)
    bad "A PYTHON SCRIPT READ THE SECRET — access is scoped to the interpreter, not to kow" ;;
  DENIED:*)
    ok "python refused (${PY_OUT}, rc $PY_RC)" ;;
  *)
    # An unexpected shape is not a pass: it might mean the probe never ran.
    bad "python probe was inconclusive: ${PY_OUT%%$'\n'*}" ;;
esac

step "9. the same rebuilt helper still reads it (stable requirement)"
# The failure this catches: a signature whose code hash changes per build
# invalidates the ACL, and every upgrade starts re-prompting.
if KOW_SIGN_ID="$CN" KOW_KEYD_OUT="$BASE/kow-keyd-rebuilt" \
     bash "$SRC/helper/build.sh" >"$BASE/build2.log" 2>&1; then
  DR2=$(codesign -d -r- "$BASE/kow-keyd-rebuilt" 2>&1 | sed -n 's/^designated => //p')
  [ "$DR1" = "$DR2" ] && ok "requirement identical across rebuilds" \
                      || bad "requirement CHANGED across rebuilds — ACLs would break on upgrade"
  GOT2=$("$BASE/kow-keyd-rebuilt" get --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" 2>/dev/null)
  [ "$GOT2" = "$SECRET" ] && ok "rebuilt binary reads the original item" \
                          || bad "rebuilt binary could not read the item"
else
  bad "rebuild failed"; tail -10 "$BASE/build2.log"
fi

step "10. delete is idempotent"
"$KEYD" delete --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" 2>/dev/null \
  && ok "deleted" || bad "delete failed"
"$KEYD" delete --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" 2>/dev/null \
  && ok "second delete is a no-op" || bad "delete is not idempotent"
"$KEYD" get --service "$SERVICE" --account "$ACCOUNT" --keychain "$KEYCHAIN" >/dev/null 2>&1
[ "$?" = 44 ] && ok "get on a missing item exits 44 (not found)" || bad "missing item did not exit 44"

printf '\n===== kow-keyd e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
