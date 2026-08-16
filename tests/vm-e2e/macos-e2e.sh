#!/usr/bin/env bash
# kow macOS end-to-end. Runs on ANY Mac — Intel or Apple Silicon, a
# contributor's laptop, a GitHub runner, or a VM — and cleans up after itself.
#
#   bash tests/vm-e2e/macos-e2e.sh              # unprivileged: no sudo, $HOME only, no residue
#   bash tests/vm-e2e/macos-e2e.sh --system     # the documented system install (see consent below)
#   bash tests/vm-e2e/macos-e2e.sh --system --keep   # leave it installed for inspection
#
# --system performs the REAL documented install: a _kow service account, a
# LaunchDaemon, directories under the Homebrew prefix, and an append-only audit
# log. It reverses every one of those on exit. Because it mutates the machine it
# is gated on KOW_E2E_CONSENT=1, and refuses outright when a kow install already
# exists, so it can never eat a real deployment.
#
# Both modes end with the same four wire assertions the Linux legs make: healthz
# 200, a placeholder swapped for the real secret upstream, an unbound
# destination refused 403, and no secret bytes in any log.
set -uo pipefail

MODE=user
KEEP=0
for a in "$@"; do
  case "$a" in
    --system) MODE=system ;;
    --keep)   KEEP=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$a" >&2; exit 2 ;;
  esac
done

PASS=0; FAIL=0
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n== %s\n' "$*"; }
red()  { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }

[ "$(uname -s)" = "Darwin" ] || { red "this leg is macOS-only (got $(uname -s))"; exit 2; }

# ---------------------------------------------------------------- environment

# Homebrew moved to /opt/homebrew on Apple Silicon; /usr/local is Intel-only.
# Hardcoding either one breaks the install on half the Macs in existence.
if [ -n "${KOW_PREFIX:-}" ]; then
  case "$KOW_PREFIX" in /*) ;; *) red "KOW_PREFIX must be an absolute path (got '$KOW_PREFIX')"; exit 2 ;; esac
  [ -d "$KOW_PREFIX" ] || { red "KOW_PREFIX does not exist: $KOW_PREFIX"; exit 2; }
  PREFIX="$KOW_PREFIX"
elif command -v brew >/dev/null 2>&1; then PREFIX="$(brew --prefix)"
elif [ -d /opt/homebrew ]; then PREFIX=/opt/homebrew
else PREFIX=/usr/local; fi

# macOS ships Python 3.9; kow needs >=3.12. Try the brew kegs first, then PATH.
find_python() {
  local c
  for c in "${KOW_PY:-}" \
           "$PREFIX/opt/python@3.14/bin/python3.14" \
           "$PREFIX/opt/python@3.13/bin/python3.13" \
           "$PREFIX/opt/python@3.12/bin/python3.12" \
           python3.14 python3.13 python3.12 python3; do
    [ -n "$c" ] || continue
    command -v -- "$c" >/dev/null 2>&1 || continue
    "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null \
      && { command -v -- "$c"; return 0; }
  done
  return 1
}
PY="$(find_python)" || {
  red "no python >=3.12 found (macOS ships 3.9). Install one: brew install python@3.13"
  exit 2
}

# Natively the tree is right here; inside a VM the runner rsyncs it to ~/kow-src.
SRC="${KOW_SRC:-$(cd "$(dirname "$0")/../.." && pwd)}"
[ -f "$SRC/pyproject.toml" ] || { red "no kow source tree at $SRC (set KOW_SRC)"; exit 2; }

printf '%s\n' "mode=$MODE  prefix=$PREFIX  python=$PY ($("$PY" -V 2>&1 | awk '{print $2}'))  src=$SRC"

REAL_SECRET="sk-live-MACTEST-$(head -c8 /dev/urandom | xxd -p)"
PLACEHOLDER="sk-PLACEHOLDER-mactest0000111122223333"
ECHO_PORT=18099

# Every file the harness itself writes lives here, so "no residue" is true for
# the logs too — not just the install. Removed by both teardowns.
RUNDIR="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e-run.XXXXXX")"

# ONE exit handler, armed here — before any of the refusal paths below can fire.
# Arming it later (inside the mode functions) leaked RUNDIR on every early exit.
# The mode teardowns self-guard on their own armed state, so this is safe to run
# no matter how far we got.
on_exit() {
  # declare -F guards the window before the mode teardowns are defined; nothing
  # currently exits in it, but a future top-level check might.
  case "$MODE" in
    user)   declare -F cleanup_user    >/dev/null && cleanup_user ;;
    system) declare -F teardown_system >/dev/null && teardown_system ;;
  esac
  [ "$KEEP" = "1" ] || rm -rf "$RUNDIR"
}
trap on_exit EXIT

# A fixed port that is already busy means the assertions could be answered by
# somebody else's proxy — a false PASS. Refuse rather than test the wrong process.
require_free_port() {
  local p="$1" what="$2"
  if nc -z 127.0.0.1 "$p" 2>/dev/null || lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1; then
    red "port $p ($what) is already in use — refusing to run, the assertions could not be trusted"
    exit 2
  fi
}

# ------------------------------------------------------------ shared upstream

ECHO_PID=""
start_echo_upstream() {
  "$PY" - "$ECHO_PORT" <<'PY' >"$RUNDIR/echo.log" 2>&1 &
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
  ECHO_PID=$!
  sleep 2
}

# The four assertions every leg in this suite makes, against a running proxy.
assert_wire_chain() {
  local port="$1" audit="$2" daemon_log="${3:-}" sudo_read="${4:-}"

  step "healthz"
  local hz
  hz=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$port" http://healthz.kow.invalid/healthz)
  [ "$hz" = "200" ] && ok "healthz.kow.invalid -> 200" || bad "healthz returned $hz"

  step "real substitution on the wire"
  local seen
  seen=$(curl -s -x "http://127.0.0.1:$port" -H "Authorization: Bearer ${PLACEHOLDER}" \
              "http://127.0.0.1:$ECHO_PORT/" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
  if [ "$seen" = "Bearer ${REAL_SECRET}" ]; then ok "upstream saw the REAL secret"
  elif [ "$seen" = "Bearer ${PLACEHOLDER}" ]; then bad "no substitution: upstream saw the placeholder unchanged"
  elif [ -z "$seen" ]; then bad "upstream saw nothing (request did not complete)"
  # Never echo the value itself: in a partial-substitution failure it IS the secret,
  # and CI logs are public.
  else bad "upstream saw an unexpected value (${#seen} bytes, withheld)"; fi

  step "deny an unbound destination"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$port" \
              -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/)
  [ "$code" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $code"

  step "audit + no secret bytes in any log"
  $sudo_read grep -q inject_decision "$audit" && ok "inject_decision audited" || bad "no inject_decision"
  if $sudo_read grep -q "$REAL_SECRET" "$audit" 2>/dev/null; then bad "SECRET IN AUDIT LOG"; else ok "no secret bytes in audit log"; fi
  if [ -n "$daemon_log" ]; then
    if $sudo_read grep -q "$REAL_SECRET" "$daemon_log" 2>/dev/null; then bad "SECRET IN DAEMON LOG"; else ok "no secret bytes in daemon log"; fi
  fi
}

write_bindings() {
  local conf="$1" secrets="$2" audit="$3"
  cat <<YAML
version: 1
binding_source: file
secrets:
  MACTEST_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {MACTEST_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: static
  config:
    type: static
    path: ${secrets}
audit:
  path: ${audit}
unmatched_destination_policy: deny
YAML
}

# ============================================================ unprivileged leg

# Deliberately NOT `local`: an EXIT trap fires after the function has returned,
# so anything scoped to it is already gone by teardown time. A teardown that
# silently sees unset paths is worse than no teardown at all.
U_BASE=""; U_PROXY_PID=""

cleanup_user() {
  [ -n "$U_PROXY_PID" ] && kill "$U_PROXY_PID" 2>/dev/null
  [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
  [ -z "$U_BASE" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept: %s (logs: %s)\n' "$U_BASE" "$RUNDIR"
  else rm -rf "$U_BASE"; fi
}

run_user_mode() {
  # mktemp, not a $$-predictable name: this path is recursively removed on exit,
  # and on a shared machine a pre-created dir or symlink here would be collateral.
  U_BASE="$(mktemp -d "${TMPDIR:-/tmp}/kow-e2e.XXXXXX")"
  local base="$U_BASE"
  local venv="$base/venv" audit="$base/audit.jsonl" log="$base/proxy.log"
  local port=14399
  export KOW_CONFDIR="$base/config"


  [ "$(id -u)" -ne 0 ] || { red "unprivileged mode must not run as root"; exit 2; }
  require_free_port "$port" "kow proxy"
  require_free_port "$ECHO_PORT" "test upstream"
  ok "running unprivileged (uid $(id -u)), nothing outside $base will be touched"

  mkdir -p "$KOW_CONFDIR/static" "$base/state"
  chmod 0700 "$base" "$base/state" "$KOW_CONFDIR" "$KOW_CONFDIR/static"

  step "1. user-local venv + install from this tree (no sudo anywhere)"
  "$PY" -m venv "$venv" >/dev/null 2>&1
  if "$venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip.log" 2>&1; then
    ok "installed into \$HOME without sudo"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip.log"; return
  fi
  "$venv/bin/kow" --version >/dev/null 2>&1 && ok "\`kow --version\` works" || bad "kow --version failed"

  step "2. config under \$KOW_CONFDIR (no /etc, no ${PREFIX})"
  # The static backend refuses a secrets file looser than 0600 in a 0700 parent.
  printf 'secrets:\n  MACTEST_KEY: "%s"\n' "$REAL_SECRET" > "$KOW_CONFDIR/static/secrets.yaml"
  chmod 0600 "$KOW_CONFDIR/static/secrets.yaml"
  write_bindings "$KOW_CONFDIR" "$KOW_CONFDIR/static/secrets.yaml" "$audit" > "$KOW_CONFDIR/bindings.yaml"
  chmod 0600 "$KOW_CONFDIR/bindings.yaml"
  ok "bindings.yaml + static secrets written under \$KOW_CONFDIR"

  step "3. run the proxy directly (no launchd, no service account)"
  HOME="$base/state" "$venv/bin/python" -m kow \
      --listen-host 127.0.0.1 --listen-port "$port" \
      --set kow_config="$KOW_CONFDIR/bindings.yaml" >"$log" 2>&1 &
  U_PROXY_PID=$!
  for _ in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$port" http://healthz.kow.invalid/healthz && break
    sleep 1
  done
  kill -0 "$U_PROXY_PID" 2>/dev/null && ok "proxy running as the calling user (pid $U_PROXY_PID)" \
    || { bad "proxy died on startup"; tail -12 "$log"; return; }

  start_echo_upstream
  assert_wire_chain "$port" "$audit" "$log" ""
}

# ============================================================== system leg

# Globals for the same reason as the user leg — the EXIT trap must still be able
# to see every path it is responsible for removing.
S_USR=_kow
S_CONF=""; S_STATE=""; S_LOGD=""; S_OPTDIR=""
S_PLIST=/Library/LaunchDaemons/io.inflightsec.kow.plist

teardown_system() {
  [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
  [ -z "$S_CONF" ] && return
  if [ "$KEEP" = "1" ]; then printf '\nkept installed (teardown skipped; logs: %s)\n' "$RUNDIR"; return; fi
  printf '\n== teardown\n'
  sudo launchctl bootout system/io.inflightsec.kow 2>/dev/null \
    || sudo launchctl unload -w "$S_PLIST" 2>/dev/null
  sudo rm -f "$S_PLIST"
  # sappnd blocks removal until it is cleared, so this must precede the rm.
  sudo chflags -R noappnd "$S_LOGD" 2>/dev/null
  sudo rm -rf "$S_CONF" "$S_STATE" "$S_LOGD" "$S_OPTDIR"
  sudo dseditgroup -o delete "$S_USR" >/dev/null 2>&1
  sudo dscl . -delete "/Users/$S_USR" >/dev/null 2>&1
  sudo dscacheutil -flushcache 2>/dev/null
  local left=""
  for p in "$S_PLIST" "$S_CONF" "$S_STATE" "$S_LOGD" "$S_OPTDIR"; do [ -e "$p" ] && left="$left $p"; done
  dscl . -read "/Groups/$S_USR" >/dev/null 2>&1 && left="$left group:$S_USR"
  dscl . -read "/Users/$S_USR" >/dev/null 2>&1 && left="$left user:$S_USR"
  [ -z "$left" ] && printf '  clean: every artifact removed\n' || red "  RESIDUE LEFT:$left"
}

run_system_mode() {
  local usr="$S_USR"
  local conf="$PREFIX/etc/kow" state="$PREFIX/var/lib/kow" logd="$PREFIX/var/log/kow"
  local optdir="$PREFIX/opt/kow"
  local plist="$S_PLIST"
  local port=14322

  if [ "${KOW_E2E_CONSENT:-}" != "1" ]; then
    cat >&2 <<EOF

REFUSING TO RUN --system WITHOUT CONSENT.

This performs the real documented install on THIS machine:
  * creates the ${usr} service account and group (dscl)
  * installs and loads a LaunchDaemon at ${plist}
  * writes ${conf}, ${state}, ${logd}, ${optdir}
  * sets the append-only system flag (chflags sappnd) on the audit log

All of it is reversed when the script exits (use --keep to retain it), but a
hard kill can leave residue. Prefer the default unprivileged mode, or a
throwaway machine such as a CI runner.

  KOW_E2E_CONSENT=1 bash $0 --system

EOF
    exit 2
  fi

  sudo -n true 2>/dev/null || sudo -v || { red "--system needs sudo"; exit 2; }

  # With no brew, PREFIX is a guess and we would be creating service directories
  # under a tree Homebrew does not manage. That is still the documented layout,
  # but say so rather than let it look deliberate.
  command -v brew >/dev/null 2>&1 \
    || printf 'note: Homebrew not found; using %s as the install prefix (set KOW_PREFIX to override)\n' "$PREFIX"

  # Never touch a real deployment. The teardown removes six paths plus the group
  # and the user, so the refusal check must cover EVERY ONE of them — anything
  # checked here but not there is a gap that destroys somebody's data. Keep the
  # two lists in step.
  local found=""
  [ -e "$plist" ]  && found="$found $plist"
  [ -e "$conf" ]   && found="$found $conf"
  [ -e "$state" ]  && found="$found $state"
  [ -e "$logd" ]   && found="$found $logd"
  [ -e "$optdir" ] && found="$found $optdir"
  dscl . -read "/Groups/$usr" >/dev/null 2>&1 && found="$found group:$usr"
  dscl . -read "/Users/$usr"  >/dev/null 2>&1 && found="$found user:$usr"
  # A job can be loaded with its plist deleted; teardown would boot out something
  # it never started.
  sudo launchctl print system/io.inflightsec.kow >/dev/null 2>&1 && found="$found launchd:io.inflightsec.kow"
  if [ -n "$found" ]; then
    red "refusing: an existing kow install was found:$found"
    red "remove it first, or run the default unprivileged mode."
    exit 2
  fi

  require_free_port "$port" "kow proxy"
  require_free_port "$ECHO_PORT" "test upstream"

  # Arm the teardown only once the pre-existing-install check has passed, so a
  # refusal can never remove someone else's deployment.
  S_CONF="$conf"; S_STATE="$state"; S_LOGD="$logd"; S_OPTDIR="$optdir"

  step "1. service account + directories + append-only audit"
  # uid/gid 250 is the stock _analyticsusers group on every Mac — derive a free one.
  local nid
  nid=$(for i in $(seq 450 550); do
          dscl . -list /Groups PrimaryGroupID | awk -v G="$i" '$2==G' | grep -q . || { echo "$i"; break; }
        done)
  # An empty nid means the whole range was taken. Without set -e the dscl calls
  # below would each fail quietly and leave a half-built account behind.
  case "$nid" in
    ''|*[!0-9]*) red "could not find a free gid in 450-550 (got '${nid}')"; exit 2 ;;
  esac
  sudo dseditgroup -o create -i "$nid" $usr
  sudo dscl . -create /Users/$usr UniqueID "$nid"
  sudo dscl . -create /Users/$usr PrimaryGroupID "$nid"
  sudo dscl . -create /Users/$usr UserShell /usr/bin/false
  sudo dscl . -create /Users/$usr NFSHomeDirectory /var/empty
  sudo dscacheutil -flushcache 2>/dev/null
  dscl . -read /Groups/$usr PrimaryGroupID >/dev/null 2>&1 \
    && ok "service group $usr has a usable gid ($nid)" || bad "group $usr has no PrimaryGroupID"

  # Prove the group name is actually usable by chown — this is what caught the
  # uid-250 collision. Use a scratch dir; never the shared /tmp.
  local canary; canary=$(mktemp -d)
  sudo chown "root:$usr" "$canary" 2>/dev/null && ok "group usable as a chown target" || bad "illegal group name for chown"
  sudo rm -rf "$canary"

  sudo install -d -o root  -g $usr -m 0750 "$conf"
  sudo install -d -o $usr  -g $usr -m 0750 "$state"
  sudo install -d -o $usr  -g $usr -m 0750 "$logd"
  sudo touch "$logd/audit.jsonl"
  sudo chown $usr:$usr "$logd/audit.jsonl"
  sudo chmod 0640 "$logd/audit.jsonl"
  sudo chflags sappnd "$logd/audit.jsonl" && ok "audit log append-only (chflags sappnd)" || bad "chflags sappnd failed"
  [ -d "$conf" ] && ok "confdir $conf created" || bad "confdir missing"

  step "2. venv + install from this tree (under $PREFIX)"
  sudo "$PY" -m venv "$optdir/.venv" >/dev/null 2>&1
  if sudo "$optdir/.venv/bin/pip" -q install "$SRC" >"$RUNDIR/pip.log" 2>&1; then
    ok "installed from source tree"
  else
    bad "install failed"; tail -8 "$RUNDIR/pip.log"; return
  fi
  "$optdir/.venv/bin/kow" --version >/dev/null 2>&1 && ok "\`kow --version\` works" || bad "kow --version failed"

  step "3. static bindings"
  sudo install -d -o $usr -g $usr -m 0700 "$conf/static"
  printf 'secrets:\n  MACTEST_KEY: "%s"\n' "$REAL_SECRET" | sudo tee "$conf/static/secrets.yaml" >/dev/null
  sudo chown $usr:$usr "$conf/static/secrets.yaml"; sudo chmod 0600 "$conf/static/secrets.yaml"
  write_bindings "$conf" "$conf/static/secrets.yaml" "$logd/audit.jsonl" | sudo tee "$conf/bindings.yaml" >/dev/null
  sudo chown "root:$usr" "$conf/bindings.yaml"; sudo chmod 0640 "$conf/bindings.yaml"
  ok "bindings.yaml + static secrets written"

  step "4. launchd daemon"
  sudo "$optdir/.venv/bin/python" - "$plist" "$usr" "$optdir" "$conf" "$state" "$logd" <<'PY'
import plistlib, sys
plist, usr, optdir, conf, state, logd = sys.argv[1:7]
plistlib.dump({
    "Label": "io.inflightsec.kow",
    "UserName": usr, "GroupName": usr,
    "ProgramArguments": [f"{optdir}/.venv/bin/python", "-m", "kow",
                         "--set", f"kow_config={conf}/bindings.yaml"],
    "EnvironmentVariables": {"HOME": state},
    "RunAtLoad": True, "KeepAlive": True,
    "StandardErrorPath": f"{logd}/stderr.log",
}, open(plist, "wb"))
PY
  sudo chown root:wheel "$plist"; sudo chmod 0644 "$plist"
  sudo launchctl load -w "$plist" 2>/dev/null
  sleep 8
  sudo launchctl print system/io.inflightsec.kow >/dev/null 2>&1 \
    && ok "launchd daemon loaded (system/io.inflightsec.kow)" || bad "daemon not registered in the system domain"
  if netstat -an 2>/dev/null | grep -q "127.0.0.1.$port.*LISTEN"; then
    ok "listening on 127.0.0.1:$port"
  else
    bad "no listener on $port"; sudo tail -12 "$logd/stderr.log" 2>/dev/null
  fi

  start_echo_upstream
  assert_wire_chain "$port" "$logd/audit.jsonl" "$logd/stderr.log" sudo
}

# ===================================================================== driver

case "$MODE" in
  user)   run_user_mode ;;
  system) run_system_mode ;;
esac

printf '\n===== kow macOS e2e (%s): %d passed, %d failed =====\n' "$MODE" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
