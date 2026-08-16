#!/usr/bin/env bash
# Runs INSIDE the Linux VM. Walks the README's own Quickstart, in order, with
# the static backend standing in for the vault. Every command the README shows a
# reader must either RUN, or be explicitly accounted for here — a README that
# drifts from the CLI fails this leg.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
skip(){ printf '  SKIP %s\n' "$*"; }
step(){ printf '\n== %s\n' "$*"; }

SRC=/home/debian/kow-src
WORK=/tmp/kow-readme; rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK/conf/static" "$WORK/state"; chmod 0700 "$WORK/conf/static" "$WORK/state"
export KOW_CONFDIR="$WORK/conf"
REAL_SECRET="sk-live-README-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PROXY_PORT=14366

VENV=$WORK/venv
python3 -m venv "$VENV" >/dev/null 2>&1
"$VENV/bin/pip" -q install "$SRC" >/tmp/readme-pip.log 2>&1 || { bad "install failed"; exit 1; }
KOW="$VENV/bin/kow"

step "README §Quickstart 1 — install"
"$KOW" --version >/dev/null 2>&1 && ok "\`kow\` on PATH after install" || bad "kow missing"
# `sudo kow setup --bws` needs a real vault token; the setup PLAN is asserted
# instead, which is the part the README is promising exists.
sudo "$KOW" setup --help >/dev/null 2>&1 && ok "\`kow setup\` exists (README step 1)" || bad "kow setup missing"
"$KOW" setup --help 2>&1 | grep -q -- '--bws' && ok "\`--bws\` flag exists as documented" || bad "--bws flag missing"

step "README §Quickstart 4 — kow env && kow run"
cat > "$WORK/conf/static/secrets.yaml" <<YAML
secrets:
  STRIPE_API_KEY: "${REAL_SECRET}"
YAML
chmod 0600 "$WORK/conf/static/secrets.yaml"
cat > "$WORK/conf/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  STRIPE_API_KEY:
    placeholder: "sk-PLACEHOLDER-readme00001111222233"
    inject:
      header: "Authorization"
      format: "Bearer {STRIPE_API_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: static
  config:
    type: static
    path: ${WORK}/conf/static/secrets.yaml
audit:
  path: ${WORK}/state/audit.jsonl
unmatched_destination_policy: deny
YAML
chmod 0600 "$WORK/conf/bindings.yaml"

ENVOUT=$("$KOW" env --config "$WORK/conf/bindings.yaml" --print 2>&1)
if echo "$ENVOUT" | grep -q "export STRIPE_API_KEY="; then
  ok "\`kow env\` projects an export line (README step 4)"
else
  bad "kow env produced no export"; echo "$ENVOUT" | head -4
fi
echo "$ENVOUT" | grep -q "$REAL_SECRET" && bad "kow env LEAKED the real secret" || ok "kow env emits only a placeholder"

"$KOW" run --help >/dev/null 2>&1 && ok "\`kow run\` exists (README step 4)" || bad "kow run missing"

step "README §Broker an MCP server"
"$KOW" mcp --help >/dev/null 2>&1 && ok "\`kow mcp\` exists" || bad "kow mcp missing"
MCPHELP=$("$KOW" mcp install --help 2>&1)
for flag in --host --env-var --server-cmd; do
  echo "$MCPHELP" | grep -q -- "$flag" && ok "\`kow mcp install $flag\` documented flag exists" || bad "missing flag $flag"
done

step "README §links — kow binding + doctor"
"$KOW" binding --help >/dev/null 2>&1 && ok "\`kow binding\` exists" || bad "kow binding missing"
"$KOW" doctor --help >/dev/null 2>&1 && ok "\`kow doctor\` exists" || bad "kow doctor missing"

step "the README's end-to-end promise: agent sends placeholder, upstream gets the key"
HOME="$WORK/state" "$VENV/bin/python" -m kow --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
  --set kow_config="$WORK/conf/bindings.yaml" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 25); do
  curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" http://healthz.kow.invalid/healthz && break
  sleep 1
done
python3 - <<'PY' >/dev/null 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=json.dumps({"auth":self.headers.get("Authorization","")}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",8095),H).serve_forever()
PY
sleep 2
PH=$(echo "$ENVOUT" | sed -n "s/^export STRIPE_API_KEY='\(.*\)'$/\1/p" | head -1)
[ -n "$PH" ] && ok "placeholder read back from \`kow env\` output" || bad "could not parse placeholder"
SEEN=$(curl -s --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" -H "Authorization: Bearer ${PH}" \
        http://127.0.0.1:8095/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "upstream received the REAL key (README's core claim)" \
  || bad "upstream saw: ${SEEN:-<nothing>}"

step "README claims no secret ever lands in logs"
if grep -q "$REAL_SECRET" "$WORK/proxy.log" 2>/dev/null; then bad "SECRET IN PROXY LOG"; else ok "no secret bytes in proxy log"; fi

kill "$PROXY_PID" 2>/dev/null
printf '\n===== README E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
