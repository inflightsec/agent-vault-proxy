#!/usr/bin/env bash
# Runs INSIDE the macOS VM. Follows the documented macOS path from
# docs/install-systemd.md (the /usr/local prefix + launchd note) for the STATIC
# backend, then asserts the same chain the Linux leg does.
set -uo pipefail

PASS=0; FAIL=0
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n== %s\n' "$*"; }

PY="${KOW_PY:-/usr/local/opt/python@3.13/bin/python3.13}"
USR=_kow
CONF=/usr/local/etc/kow
STATE=/usr/local/var/lib/kow
LOGD=/usr/local/var/log/kow
PLIST=/Library/LaunchDaemons/io.inflightsec.kow.plist
REAL_SECRET="sk-live-MACTEST-$(head -c8 /dev/urandom | xxd -p)"
PLACEHOLDER="sk-PLACEHOLDER-mactest0000111122223333"

step "0. interpreter (kow requires >=3.12; macOS ships 3.9)"
"$PY" -V >/dev/null 2>&1 && ok "python $("$PY" -V 2>&1 | awk '{print $2}')" || { bad "no python >=3.12"; exit 1; }

step "1. service account + directories + append-only audit (doc §1 macOS)"
# Derive a free id — 250 is the stock _analyticsusers GID on every Mac.
if ! dscl . -read /Groups/$USR PrimaryGroupID >/dev/null 2>&1; then
  sudo dseditgroup -o delete $USR >/dev/null 2>&1
  sudo dscl . -delete /Users/$USR >/dev/null 2>&1
  NID=$(for i in $(seq 450 550); do dscl . -list /Groups PrimaryGroupID | awk -v G=$i '$2==G' | grep -q . || { echo $i; break; }; done)
  sudo dseditgroup -o create -i "$NID" $USR
  sudo dscl . -create /Users/$USR  UniqueID "$NID"
  sudo dscl . -create /Users/$USR  PrimaryGroupID "$NID"
  sudo dscl . -create /Users/$USR  UserShell /usr/bin/false
  sudo dscl . -create /Users/$USR  NFSHomeDirectory /var/empty
  sudo dscacheutil -flushcache 2>/dev/null
fi
dscl . -read /Groups/$USR PrimaryGroupID >/dev/null 2>&1 \
  && ok "service group $USR has a usable gid" || bad "group $USR has no PrimaryGroupID"
sudo chown root:$USR /tmp 2>/dev/null; sudo chown root:wheel /tmp 2>/dev/null
sudo install -d -o root -g $USR -m 0750 "$CONF"
sudo install -d -o $USR -g $USR -m 0750 "$STATE"
sudo install -d -o $USR -g $USR -m 0750 "$LOGD"
sudo touch "$LOGD/audit.jsonl"; sudo chown $USR:$USR "$LOGD/audit.jsonl"; sudo chmod 0640 "$LOGD/audit.jsonl"
sudo chflags sappnd "$LOGD/audit.jsonl" && ok "audit log append-only (chflags sappnd)" || bad "chflags sappnd failed"
[ -d "$CONF" ] && ok "confdir $CONF created" || bad "confdir missing"

step "2. venv + install from this tree (doc §2, /usr/local prefix)"
sudo "$PY" -m venv /usr/local/opt/kow/.venv >/dev/null 2>&1
if sudo /usr/local/opt/kow/.venv/bin/pip -q install ~/kow-src >/tmp/pipinstall.log 2>&1; then
  ok "installed from source tree"
else
  bad "install failed"; tail -8 /tmp/pipinstall.log; exit 1
fi
/usr/local/opt/kow/.venv/bin/kow --version >/dev/null 2>&1 && ok "\`kow --version\` works" || bad "kow --version failed"

step "3. static bindings (doc §3)"
# The static backend refuses anything looser than 0600 inside a 0700 parent
# (backends/static._file_is_safe) — it holds plaintext secrets. The shared
# confdir is 0750 for bindings.yaml, so the secrets file gets its own dir.
sudo install -d -o $USR -g $USR -m 0700 "$CONF/static"
sudo tee "$CONF/static/secrets.yaml" >/dev/null <<YAML
secrets:
  MACTEST_KEY: "${REAL_SECRET}"
YAML
sudo chown $USR:$USR "$CONF/static/secrets.yaml"
sudo chmod 0600 "$CONF/static/secrets.yaml"
sudo tee "$CONF/bindings.yaml" >/dev/null <<YAML
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
    path: ${CONF}/static/secrets.yaml
audit:
  path: ${LOGD}/audit.jsonl
unmatched_destination_policy: deny
YAML
sudo sh -c "chown root:$USR $CONF/bindings.yaml; chmod 0640 $CONF/bindings.yaml"
ok "bindings.yaml + static-secrets.yaml written"

step "4. launchd daemon (doc §4 macOS note)"
sudo /usr/local/opt/kow/.venv/bin/python - "$PLIST" <<PY
import plistlib, sys
plistlib.dump({
    "Label": "io.inflightsec.kow",
    "UserName": "$USR", "GroupName": "$USR",
    "ProgramArguments": ["/usr/local/opt/kow/.venv/bin/python", "-m", "kow",
                         "--set", "kow_config=$CONF/bindings.yaml"],
    "EnvironmentVariables": {"HOME": "$STATE"},
    "RunAtLoad": True, "KeepAlive": True,
    "StandardErrorPath": "$LOGD/stderr.log",
}, open(sys.argv[1], "wb"))
PY
sudo chown root:wheel "$PLIST"; sudo chmod 0644 "$PLIST"
sudo launchctl load -w "$PLIST" 2>/dev/null
sleep 8
sudo launchctl list | grep -q io.inflightsec.kow && ok "launchd daemon loaded" || bad "daemon not in launchctl list"
if netstat -an 2>/dev/null | grep -q '127.0.0.1.14322.*LISTEN'; then ok "listening on 127.0.0.1:14322"; else bad "no listener on 14322"; sudo tail -12 "$LOGD/stderr.log" 2>/dev/null; fi

step "5. healthz"
HZ=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:14322 http://healthz.kow.invalid/healthz)
[ "$HZ" = "200" ] && ok "healthz.kow.invalid -> 200" || bad "healthz returned $HZ"

step "6. real substitution on the wire"
"$PY" - <<'PY' >/tmp/echo.log 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization","")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",8099),H).serve_forever()
PY
sleep 2
SEEN=$(curl -s -x http://127.0.0.1:14322 -H "Authorization: Bearer ${PLACEHOLDER}" http://127.0.0.1:8099/ | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "upstream saw the REAL secret" || bad "upstream saw: ${SEEN}"

step "7. deny an unbound destination"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:14322 -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/)
[ "$CODE" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $CODE"

step "8. audit + no secret bytes"
sudo grep -q inject_decision "$LOGD/audit.jsonl" && ok "inject_decision audited" || bad "no inject_decision"
if sudo grep -q "$REAL_SECRET" "$LOGD/audit.jsonl" 2>/dev/null; then bad "SECRET IN AUDIT LOG"; else ok "no secret bytes in audit log"; fi
if sudo grep -q "$REAL_SECRET" "$LOGD/stderr.log" 2>/dev/null; then bad "SECRET IN DAEMON LOG"; else ok "no secret bytes in daemon log"; fi

printf '\n===== macOS VM E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
