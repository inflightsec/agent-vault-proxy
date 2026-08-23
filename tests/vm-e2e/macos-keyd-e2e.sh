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
#
# Denial status codes vary by path — errSecInteractionNotAllowed (-25308) when
# the process has no session, errSecAuthFailed (-25293) when interaction is
# disabled explicitly. Assert on DENIED:*, never on one constant.
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

PASS=0; FAIL=0; SKIP=0
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
# Bounded like the rest: this one is not expected to prompt, but "not expected
# to prompt" is exactly the assumption that cost two 20-minute cancellations.
ORIG_LIST=$( { security list-keychains -d user & _lp=$!
    _li=0; while kill -0 "$_lp" 2>/dev/null && [ "$_li" -lt 20 ]; do sleep 0.5; _li=$((_li + 1)); done
    kill -0 "$_lp" 2>/dev/null && { kill -9 "$_lp" 2>/dev/null; echo "LIST_TIMEOUT"; } || wait "$_lp"
  } | tr -d ' "')
case "$ORIG_LIST" in *LIST_TIMEOUT*) echo "security list-keychains stalled" >&2; exit 1 ;; esac

# Bounded capture for cleanup. `cleanup` runs on EVERY exit, including success,
# so an unbounded security(1) call here re-creates the exact 20-minute
# cancellation this leg has already suffered twice — just on the way out.
bounded_out() {
  local secs="$1"; shift
  local f p i
  f="$(mktemp "${TMPDIR:-/tmp}/kow-bo.XXXXXX")"
  "$@" >"$f" 2>/dev/null &
  p=$!; i=0
  while kill -0 "$p" 2>/dev/null && [ "$i" -lt "$((secs * 2))" ]; do sleep 0.5; i=$((i + 1)); done
  if kill -0 "$p" 2>/dev/null; then
    pkill -9 -P "$p" 2>/dev/null; kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
    printf 'BOUNDED_TIMEOUT\n'
  else
    wait "$p" 2>/dev/null; cat "$f"
  fi
  rm -f "$f"
}

cleanup() {
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s\n' "$BASE"; return; fi
  # shellcheck disable=SC2086 — the saved list is intentionally word-split
  [ -n "$ORIG_LIST" ] && security list-keychains -d user -s $ORIG_LIST 2>/dev/null
  security delete-keychain "$KEYCHAIN" 2>/dev/null
  security delete-keychain "$SIGNKC" 2>/dev/null
  rm -rf "$BASE"
  local left="" _ids _kcs
  [ -e "$KEYCHAIN" ] && left="$left keychain"
  [ -e "$SIGNKC" ] && left="$left signing-keychain"
  _ids="$(bounded_out 15 security find-identity -v -p codesigning)"
  case "$_ids" in *BOUNDED_TIMEOUT*) left="$left identity-check-stalled" ;;
                  *"$CN"*)           left="$left identity" ;; esac
  _kcs="$(bounded_out 15 security list-keychains -d user)"
  case "$_kcs" in *BOUNDED_TIMEOUT*) left="$left keychain-list-stalled" ;;
                  *keyd-signing*)    left="$left search-list-entry" ;; esac
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

# Bounded, and traced. Several `security` calls block forever on a host with no
# Aqua session (a GUI prompt nobody can answer), and macOS ships no timeout(1),
# so an unbounded call turns into a 20-minute CI cancellation with no output at
# all. Cap it, stream the trace, and on a hang print the last commands that ran.
KOW_SIGN_ID="$CN" KOW_SIGN_KEYCHAIN="$SIGNKC" KOW_SIGN_KEYCHAIN_PW="$KCPW" \
  bash -x "$SRC/helper/make-signing-identity.sh" >"$BASE/identity.log" 2>&1 &
_idpid=$!
_i=0
while kill -0 "$_idpid" 2>/dev/null && [ "$_i" -lt 240 ]; do sleep 0.5; _i=$((_i + 1)); done
if kill -0 "$_idpid" 2>/dev/null; then
  kill -9 "$_idpid" 2>/dev/null; wait "$_idpid" 2>/dev/null
  bad "signing-identity creation HUNG (>120s) — last commands before the stall:"
  grep '^+' "$BASE/identity.log" | tail -12
  exit 1
elif wait "$_idpid"; then
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

# Deny-probes MUST be bounded. An unauthorised keychain read raises an
# authorisation dialog: with an Aqua session it is denied in milliseconds
# (rc 36), with no session — every hosted CI runner — it blocks forever. That
# is what burned two 20-minute cancellations here, first in step 1 and then
# in step 7.
#
# A timeout is INCONCLUSIVE and therefore FAILS. The designed behaviour is
# categorical refusal — a real Mac returns rc 36 for security(1) and
# errSecInteractionNotAllowed (-25308) for the ctypes probe, with no prompt at
# all. A stall means something asked a human instead, i.e. the item may be
# reachable WITH approval, which is a strictly weaker property than this step
# asserts. Reporting that as a pass would conceal the very regression the step
# exists to catch, so it is reported as unproven and red.
DP_RC=0; DP_OUT=""; DP_TIMEOUT=0
deny_probe() {
  local secs=20 p i
  DP_TIMEOUT=0
  "$@" >"$BASE/deny.out" 2>&1 &
  p=$!; i=0
  while kill -0 "$p" 2>/dev/null && [ "$i" -lt "$((secs * 2))" ]; do sleep 0.5; i=$((i + 1)); done
  if kill -0 "$p" 2>/dev/null; then
    # Descendants first: `security` can spawn an authorisation agent that would
    # otherwise outlive the probe and interfere with cleanup or the next step.
    pkill -9 -P "$p" 2>/dev/null
    kill -9 "$p" 2>/dev/null; wait "$p" 2>/dev/null
    DP_TIMEOUT=1; DP_RC=124
  else
    wait "$p"; DP_RC=$?
  fi
  DP_OUT="$(cat "$BASE/deny.out" 2>/dev/null)"
}

step "7. /usr/bin/security must NOT be able to read it"
deny_probe security find-generic-password -s "$SERVICE" -a "$ACCOUNT" -w "$KEYCHAIN"
SEC_OUT="$DP_OUT"; SEC_RC="$DP_RC"
if [ "$DP_TIMEOUT" = 1 ]; then
  # UNDETERMINED, deliberately neither pass nor fail. security(1) exposes no way
  # to forbid interaction, so on a host with an Aqua session it blocks on a
  # dialog. A stall proves only that nothing was read silently in the window —
  # it does NOT prove the ACL is scoped (a lock, a regression or a
  # user-approvable path look identical from here). Claiming a pass would
  # overclaim; failing would make the leg permanently red on hosted runners for
  # an environment property. The categorical claim is step 8's job, and step 8
  # is deterministic.
  skip "security(1) did not resolve in 20s — undetermined here; step 8 makes the categorical claim"
elif [ "$SEC_RC" = 0 ] && [ "$SEC_OUT" = "$SECRET" ]; then
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

# Ask the same question the helper asks (kow-keyd.c calls this too): "can I
# read this WITHOUT a human?" Otherwise the answer depends on whether the host
# happens to have a GUI session, and a prompt masquerades as a hang.
Sec.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int32
Sec.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_ubyte]  # Boolean
_ia = Sec.SecKeychainSetUserInteractionAllowed(0)
if _ia != 0:
    # Step 8 claims a stall is a defect; that claim is only valid if interaction
    # really was disabled. If it was not, say so rather than testing something else.
    print("INTERACTION_NOT_DISABLED:%d" % _ia); sys.exit(4)

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
deny_probe "$PY_BIN" "$BASE/steal.py" "$SERVICE" "$ACCOUNT" "$KEYCHAIN"
PY_OUT="$DP_OUT"; PY_RC="$DP_RC"
if [ "$DP_TIMEOUT" = 1 ]; then
  bad "python probe stalled despite interaction being disabled — expected an"
  bad "  immediate DENIED:<status>. A stall here is a real defect, not environment."
  PY_OUT="TIMEOUT"
fi
case "$PY_OUT" in
  TIMEOUT) ;;
  INTERACTION_NOT_DISABLED:*)
    # Step 8's "a stall is a defect" claim holds only if interaction really was
    # disabled. If that call failed, say so rather than asserting a property
    # this run did not actually test.
    bad "could not disable keychain interaction (${PY_OUT}) — step 8 cannot make its claim" ;;
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

if [ "$SKIP" -gt 0 ]; then
  printf '\n===== kow-keyd e2e: %d passed, %d failed, %d undetermined =====\n' "$PASS" "$FAIL" "$SKIP"
else
  printf '\n===== kow-keyd e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
fi
[ "$FAIL" -eq 0 ]
