#!/usr/bin/env bash
# Runs INSIDE the Linux VM as an UNPRIVILEGED user. No sudo, no /etc, no system
# service, no service account — the single-developer install: a venv under
# $HOME, config under $KOW_CONFDIR, the proxy run directly.
#
# This is the leg that proves kow does not *require* root to broker.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step(){ printf '\n== %s\n' "$*"; }

[ "$(id -u)" -ne 0 ] && ok "running unprivileged (uid $(id -u))" || { echo "  FAIL must not run as root"; exit 1; }

PREFIX="$HOME/.local/share/kow"
export KOW_CONFDIR="$HOME/.config/kow"
STATE="$HOME/.local/state/kow"
REAL_SECRET="sk-live-ROOTLESS-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PLACEHOLDER="sk-PLACEHOLDER-rootless000011112222333"
PROXY_PORT=14399

# Recorded BEFORE we do anything, so a system install from another leg in
# the same VM is not mistaken for something this leg created.
ETC_SNAPSHOT=""; [ -e /etc/kow ] && ETC_SNAPSHOT=/etc/kow
mkdir -p "$KOW_CONFDIR/static" "$STATE" "$PREFIX"
chmod 0700 "$KOW_CONFDIR" "$KOW_CONFDIR/static" "$STATE"

step "1. user-local venv + install (no sudo anywhere)"
python3 -m venv "$PREFIX/.venv" >/dev/null 2>&1
if "$PREFIX/.venv/bin/pip" -q install "$HOME/kow-src" >/tmp/rootless-pip.log 2>&1; then
  ok "installed into \$HOME without sudo"
else
  bad "install failed"; tail -8 /tmp/rootless-pip.log; exit 1
fi
"$PREFIX/.venv/bin/kow" --version >/dev/null 2>&1 && ok "kow --version works" || bad "kow --version failed"

step "2. config under \$KOW_CONFDIR (no /etc)"
cat > "$KOW_CONFDIR/static/secrets.yaml" <<YAML
secrets:
  ROOTLESS_KEY: "${REAL_SECRET}"
YAML
chmod 0600 "$KOW_CONFDIR/static/secrets.yaml"
cat > "$KOW_CONFDIR/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  ROOTLESS_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {ROOTLESS_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: static
  config:
    type: static
    path: ${KOW_CONFDIR}/static/secrets.yaml
audit:
  path: ${STATE}/audit.jsonl
unmatched_destination_policy: deny
YAML
chmod 0600 "$KOW_CONFDIR/bindings.yaml"
# Another leg may have installed system-wide in this same VM; what matters
# is that THIS leg touched nothing outside $HOME.
if [ -e /etc/kow ] && [ ! -e "$ETC_SNAPSHOT" ]; then
  bad "this leg created /etc/kow"
else
  ok "no system paths created by this leg"
fi
ok "config under \$KOW_CONFDIR"

step "3. run the proxy as this user on an unprivileged port"
HOME="$STATE" "$PREFIX/.venv/bin/python" -m kow \
  --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
  --set kow_config="$KOW_CONFDIR/bindings.yaml" >/tmp/rootless-proxy.log 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 25); do
  curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" http://healthz.kow.invalid/healthz && break
  sleep 1
done
kill -0 "$PROXY_PID" 2>/dev/null && ok "proxy running as uid $(id -u) (pid $PROXY_PID)" \
  || { bad "proxy died"; tail -12 /tmp/rootless-proxy.log; exit 1; }
HZ=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PROXY_PORT" http://healthz.kow.invalid/healthz)
[ "$HZ" = "200" ] && ok "healthz -> 200" || bad "healthz returned $HZ"

step "4. real substitution on the wire"
python3 - <<'PY' >/tmp/rootless-echo.log 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization","")}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1", 8097), H).serve_forever()
PY
ECHO_PID=$!
sleep 2
SEEN=$(curl -s --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" -H "Authorization: Bearer ${PLACEHOLDER}" \
        http://127.0.0.1:8097/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "upstream saw the REAL secret" || bad "upstream saw: ${SEEN:-<nothing>}"

step "5. deny an unbound destination"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -x "http://127.0.0.1:$PROXY_PORT" -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/)
[ "$CODE" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $CODE"

step "6. audit under \$HOME, no secret bytes"
grep -q inject_decision "$STATE/audit.jsonl" 2>/dev/null && ok "inject_decision audited to \$HOME" || bad "no audit in \$HOME"
if grep -q "$REAL_SECRET" "$STATE/audit.jsonl" 2>/dev/null; then bad "SECRET IN AUDIT"; else ok "no secret bytes in audit log"; fi
if grep -q "$REAL_SECRET" /tmp/rootless-proxy.log 2>/dev/null; then bad "SECRET IN PROXY LOG"; else ok "no secret bytes in proxy log"; fi

kill "$PROXY_PID" "$ECHO_PID" 2>/dev/null
printf '\n===== rootless E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
