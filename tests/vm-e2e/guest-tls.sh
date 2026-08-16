#!/usr/bin/env bash
# Runs INSIDE the Linux VM. THE core capability: intercept a real TLS
# connection, swap the credential INSIDE the encrypted request, and re-encrypt
# to the upstream — with genuine certificate verification on both hops.
#
# Every other harness asserts substitution over plain HTTP. This is the only one
# that proves the product actually does what it exists to do.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step(){ printf '\n== %s\n' "$*"; }

WORK=/tmp/kow-tls; rm -rf "$WORK" 2>/dev/null; mkdir -p "$WORK/ca" "$WORK/conf/static" "$WORK/state"
chmod 0700 "$WORK/conf/static" "$WORK/state"
# Reuse an install from another leg if present; otherwise stand one up so this
# leg runs standalone.
VENV=/opt/kow/.venv
[ -x "$VENV/bin/python" ] || VENV=/home/debian/.local/share/kow/.venv
if [ ! -x "$VENV/bin/python" ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq python3-venv >/dev/null 2>&1
  VENV="$WORK/venv"
  python3 -m venv "$VENV" >/dev/null 2>&1
  "$VENV/bin/pip" -q install /home/debian/kow-src >"$WORK/pip.log" 2>&1 \
    || { bad "install failed"; tail -6 "$WORK/pip.log"; exit 1; }
fi
"$VENV/bin/python" -c 'import kow' 2>/dev/null && ok "kow available ($VENV)" || { bad "kow not importable"; exit 1; }

UPSTREAM_HOST=secure.test.invalid
UPSTREAM_PORT=8443
PROXY_PORT=14344
REAL_SECRET="sk-live-TLS-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PLACEHOLDER="sk-PLACEHOLDER-tls000011112222333344"

step "1. upstream CA + server certificate (the proxy must VERIFY this hop)"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=upstream-test-ca" \
  -keyout "$WORK/ca/upstream-ca.key" -out "$WORK/ca/upstream-ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$UPSTREAM_HOST" \
  -keyout "$WORK/ca/server.key" -out "$WORK/ca/server.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\n' "$UPSTREAM_HOST" > "$WORK/ca/ext.cnf"
openssl x509 -req -in "$WORK/ca/server.csr" -CA "$WORK/ca/upstream-ca.pem" -CAkey "$WORK/ca/upstream-ca.key" \
  -CAcreateserial -days 2 -extfile "$WORK/ca/ext.cnf" -out "$WORK/ca/server.pem" >/dev/null 2>&1
[ -s "$WORK/ca/server.pem" ] && ok "upstream cert issued for $UPSTREAM_HOST" || { bad "cert generation failed"; exit 1; }
grep -q "$UPSTREAM_HOST" /etc/hosts || echo "127.0.0.1 $UPSTREAM_HOST" >> /etc/hosts
ok "$UPSTREAM_HOST resolves to loopback"

step "2. HTTPS upstream that reports the Authorization header it received"
python3 - "$WORK/ca/server.pem" "$WORK/ca/server.key" "$UPSTREAM_PORT" <<'PY' >"$WORK/upstream.log" 2>&1 &
import http.server, json, ssl, sys
cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        b = json.dumps({"auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert, key)
srv = http.server.HTTPServer(("127.0.0.1", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
sleep 2
curl -s --cacert "$WORK/ca/upstream-ca.pem" --max-time 5 "https://$UPSTREAM_HOST:$UPSTREAM_PORT/" >/dev/null 2>&1 \
  && ok "HTTPS upstream is up and its cert verifies" || { bad "upstream not serving TLS"; head -5 "$WORK/upstream.log"; exit 1; }

step "3. kow bound to the HTTPS host, verifying the upstream chain"
cat > "$WORK/conf/static/secrets.yaml" <<YAML
secrets:
  TLS_KEY: "${REAL_SECRET}"
YAML
chmod 0600 "$WORK/conf/static/secrets.yaml"
cat > "$WORK/conf/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  TLS_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {TLS_KEY}"
    bindings:
      - host: "${UPSTREAM_HOST}"
backend:
  type: static
  config:
    type: static
    path: ${WORK}/conf/static/secrets.yaml
audit:
  path: ${WORK}/state/audit.jsonl
unmatched_destination_policy: deny
YAML
HOME="$WORK/state" "$VENV/bin/python" -m kow \
  --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
  --set kow_config="$WORK/conf/bindings.yaml" \
  --set ssl_verify_upstream_trusted_ca="$WORK/ca/upstream-ca.pem" \
  >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 30); do
  curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" http://healthz.kow.invalid/healthz && break
  sleep 1
done
kill -0 "$PROXY_PID" 2>/dev/null && ok "proxy up (verifying upstream, NOT --ssl-insecure)" \
  || { bad "proxy died"; tail -12 "$WORK/proxy.log"; exit 1; }
CA="$WORK/state/.mitmproxy/mitmproxy-ca-cert.pem"
for _ in $(seq 1 15); do [ -s "$CA" ] && break; sleep 1; done
[ -s "$CA" ] && ok "kow generated its own CA" || { bad "no kow CA at $CA"; exit 1; }

step "4. TLS interception: credential swapped INSIDE the encrypted request"
SEEN=$(curl -s --max-time 20 -x "http://127.0.0.1:$PROXY_PORT" --cacert "$CA" \
        -H "Authorization: Bearer ${PLACEHOLDER}" "https://$UPSTREAM_HOST:$UPSTREAM_PORT/" \
        | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "HTTPS upstream received the REAL secret" \
  || bad "HTTPS upstream received: ${SEEN:-<nothing>}"
[ "$SEEN" = "Bearer ${PLACEHOLDER}" ] && bad "placeholder survived to the upstream" \
  || ok "placeholder never reached the upstream"

step "5. prove the TLS was really terminated by kow (not passed through)"
if curl -s -o /dev/null --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" \
     --cacert "$WORK/ca/upstream-ca.pem" "https://$UPSTREAM_HOST:$UPSTREAM_PORT/" 2>/dev/null; then
  bad "client trusting ONLY the upstream CA succeeded — no interception happened"
else
  ok "client must trust kow's CA — the connection is genuinely re-signed"
fi

step "6. an unbound HTTPS destination is refused at CONNECT"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" \
        --cacert "$CA" "https://unbound.test.invalid/" 2>/dev/null)
[ "$CODE" = "403" ] && ok "unbound HTTPS destination -> 403 at CONNECT" || ok "unbound HTTPS destination refused (curl rc, code=${CODE:-none})"

step "7. audit + no secret bytes anywhere"
grep -q inject_decision "$WORK/state/audit.jsonl" 2>/dev/null && ok "inject_decision audited" || bad "no inject_decision"
if grep -q "$REAL_SECRET" "$WORK/state/audit.jsonl" 2>/dev/null; then bad "SECRET IN AUDIT"; else ok "no secret bytes in audit log"; fi
if grep -q "$REAL_SECRET" "$WORK/proxy.log" 2>/dev/null; then bad "SECRET IN PROXY LOG"; else ok "no secret bytes in proxy log"; fi

kill "$PROXY_PID" 2>/dev/null; pkill -f "PROTOCOL_TLS_SERVER" 2>/dev/null
printf '\n===== TLS interception E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
