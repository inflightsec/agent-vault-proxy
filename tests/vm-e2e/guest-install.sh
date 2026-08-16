#!/usr/bin/env bash
# Runs INSIDE the VM as root. Follows docs/install-systemd.md step by step for
# the STATIC backend, then asserts the end state end-to-end: service active,
# listener up, healthz 200, a real placeholder swapped on the wire, a real deny,
# and no secret bytes in any log.
#
# Deliberately uses the DOCUMENTED commands, not the installer, so a doc that
# drifts from reality fails here.
set -uo pipefail

PASS=0; FAIL=0
ok()   { printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step() { printf '\n== %s\n' "$*"; }

REAL_SECRET="sk-live-VMTEST-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PLACEHOLDER="sk-PLACEHOLDER-vmtest0000111122223333"

step "0. prerequisites (doc §Prerequisites: python3 + venv)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/tmp/apt.log 2>&1
if apt-get install -y -qq python3-venv e2fsprogs iproute2 curl >>/tmp/apt.log 2>&1; then
  ok "python3-venv + tools installed"
else
  bad "apt install failed (no guest egress?)"; tail -5 /tmp/apt.log
fi

step "1. user, directories, append-only audit log (doc §1)"
useradd --system --no-create-home --shell /usr/sbin/nologin kow 2>/dev/null || true
install -d -o root -g kow -m 0750 /etc/kow
install -d -o kow  -g kow -m 0750 /var/lib/kow
install -d -o kow  -g kow -m 0750 /var/log/kow
install -d -o root -g root -m 0755 /opt/kow
touch /var/log/kow/audit.jsonl
chown kow:kow /var/log/kow/audit.jsonl
chmod 0640    /var/log/kow/audit.jsonl
chattr +a     /var/log/kow/audit.jsonl && ok "audit log is append-only (chattr +a)" \
  || bad "chattr +a failed"
[ -d /etc/kow ] && ok "confdir /etc/kow created" || bad "confdir missing"

step "2. system-wide venv + install (doc §2)"
python3 -m venv /opt/kow/.venv
/opt/kow/.venv/bin/pip -q install --upgrade pip >/dev/null 2>&1
if /opt/kow/.venv/bin/pip -q install /home/debian/kow-src >/tmp/pipinstall.log 2>&1; then
  ok "installed from source tree"
else
  bad "install failed"; tail -12 /tmp/pipinstall.log; exit 1
fi
/opt/kow/.venv/bin/kow --version >/dev/null 2>&1 && ok "\`kow\` entrypoint runs" || bad "kow entrypoint missing"
/opt/kow/.venv/bin/avp --version >/dev/null 2>&1 && ok "back-compat \`avp\` entrypoint runs" || bad "avp entrypoint missing"

step "3. static-backend bindings (doc §3, static route)"
cat > /etc/kow/static-secrets.yaml <<YAML
secrets:
  VMTEST_KEY: "${REAL_SECRET}"
YAML
chown root:kow /etc/kow/static-secrets.yaml; chmod 0640 /etc/kow/static-secrets.yaml
cat > /etc/kow/bindings.yaml <<YAML
version: 1
binding_source: file
secrets:
  VMTEST_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {VMTEST_KEY}"
    bindings:
      - host: "127.0.0.1"
backend:
  type: static
  config:
    type: static
    path: /etc/kow/static-secrets.yaml
audit:
  path: /var/log/kow/audit.jsonl
unmatched_destination_policy: deny
YAML
chown root:kow /etc/kow/bindings.yaml; chmod 0640 /etc/kow/bindings.yaml
ok "bindings.yaml + static-secrets.yaml written"

step "4. systemd unit from docs/systemd-unit.md (doc §4)"
cp /home/debian/kow.service /etc/systemd/system/kow.service
systemctl daemon-reload
systemctl enable --now kow >/dev/null 2>&1
sleep 6
systemctl is-active --quiet kow && ok "systemctl is-active kow" || { bad "service not active"; journalctl -u kow -n 40 --no-pager; }
ss -tln | grep -q '127.0.0.1:14322' && ok "listening on 127.0.0.1:14322" || bad "no listener on 14322"

step "5. healthz through the proxy"
HZ=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:14322 http://healthz.kow.invalid/healthz)
[ "$HZ" = "200" ] && ok "healthz.kow.invalid -> 200" || bad "healthz returned $HZ"
HZL=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:14322 http://healthz.agent-vault-proxy.invalid/healthz)
[ "$HZL" = "200" ] && ok "legacy healthz host still answered -> 200" || bad "legacy healthz returned $HZL"

step "6. real substitution on the wire"
python3 - <<'PY' > /tmp/echo.log 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"auth": self.headers.get("Authorization", "")}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8099), H).serve_forever()
PY
sleep 2
SEEN=$(curl -s -x http://127.0.0.1:14322 -H "Authorization: Bearer ${PLACEHOLDER}" http://127.0.0.1:8099/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])')
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "upstream saw the REAL secret" || bad "upstream saw: ${SEEN}"
echo "$SEEN" | grep -q "PLACEHOLDER" && bad "placeholder leaked upstream" || ok "placeholder did not reach upstream"

step "7. deny an unbound destination"
CODE=$(curl -s -o /dev/null -w '%{http_code}' -x http://127.0.0.1:14322 -H "Authorization: Bearer ${PLACEHOLDER}" http://198.51.100.7/ )
[ "$CODE" = "403" ] && ok "unbound destination -> 403" || bad "unbound destination -> $CODE"

step "8. audit written, and NO secret bytes anywhere"
grep -q inject_decision /var/log/kow/audit.jsonl && ok "inject_decision audited" || bad "no inject_decision in audit"
if grep -rq "$REAL_SECRET" /var/log/kow/audit.jsonl 2>/dev/null; then bad "REAL SECRET FOUND IN AUDIT LOG"; else ok "no secret bytes in audit log"; fi
if journalctl -u kow --no-pager 2>/dev/null | grep -q "$REAL_SECRET"; then bad "REAL SECRET FOUND IN JOURNAL"; else ok "no secret bytes in journald"; fi

step "9. CA generation + confdir hardening (doc §5)"
curl -s -x http://127.0.0.1:14322 https://example.invalid -o /dev/null 2>/dev/null || true
sudo -u kow /opt/kow/.venv/bin/python -c "
from pathlib import Path
from mitmproxy.certs import CertStore
CertStore.from_store(Path('/var/lib/kow/.mitmproxy'), 'mitmproxy', 2048, None)" >/dev/null 2>&1
chmod 0700 /var/lib/kow/.mitmproxy
MODE=$(stat -c '%a' /var/lib/kow/.mitmproxy)
[ "$MODE" = "700" ] && ok "CA confdir is 0700 (ADR-0012)" || bad "CA confdir mode is $MODE"

step "10. kow doctor"
/opt/kow/.venv/bin/kow doctor >/tmp/doctor.log 2>&1 && ok "kow doctor exits 0" || { bad "kow doctor failed"; tail -5 /tmp/doctor.log; }

printf '\n===== VM E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
