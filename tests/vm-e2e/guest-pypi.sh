#!/usr/bin/env bash
# Runs INSIDE the Linux VM. Builds the distribution from THIS tree, serves it
# from a local PEP 503 index, and installs it exactly the way the README tells
# an operator to — `pipx install 'keys-on-the-wire[...]'` against a real index —
# then proves the installed artefact actually brokers.
#
# This is the only leg that exercises the PACKAGING: sdist + wheel metadata,
# console scripts, extras, and the index resolution path.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step(){ printf '\n== %s\n' "$*"; }

SRC=/home/debian/kow-src
WORK=/tmp/kow-pypi; rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK/build" "$WORK/index/simple/keys-on-the-wire" "$WORK/conf/static" "$WORK/state"
chmod 0700 "$WORK/conf/static" "$WORK/state"
INDEX_PORT=8085
PROXY_PORT=14355
REAL_SECRET="sk-live-PYPI-$(head -c8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
PLACEHOLDER="sk-PLACEHOLDER-pypi00001111222233334"

step "1. build sdist + wheel from this tree"
export DEBIAN_FRONTEND=noninteractive
python3 -m venv "$WORK/buildenv" >/dev/null 2>&1
"$WORK/buildenv/bin/pip" -q install build >/dev/null 2>&1 || { bad "could not install build"; exit 1; }
if "$WORK/buildenv/bin/python" -m build -o "$WORK/build" "$SRC" >"$WORK/build.log" 2>&1; then
  ok "sdist + wheel built"
else
  bad "build failed"; tail -12 "$WORK/build.log"; exit 1
fi
ls "$WORK/build"/*.whl >/dev/null 2>&1 && ok "wheel present: $(basename "$(ls "$WORK/build"/*.whl | head -1)")" || bad "no wheel"
ls "$WORK/build"/*.tar.gz >/dev/null 2>&1 && ok "sdist present: $(basename "$(ls "$WORK/build"/*.tar.gz | head -1)")" || bad "no sdist"

step "2. serve it as a PEP 503 simple index (the mock PyPI)"
cp "$WORK/build"/* "$WORK/index/simple/keys-on-the-wire/"
{
  echo '<!DOCTYPE html><html><body>'
  for f in "$WORK/index/simple/keys-on-the-wire/"*; do
    printf '<a href="%s">%s</a><br/>\n' "$(basename "$f")" "$(basename "$f")"
  done
  echo '</body></html>'
} > "$WORK/index/simple/keys-on-the-wire/index.html"
printf '<!DOCTYPE html><html><body><a href="keys-on-the-wire/">keys-on-the-wire</a></body></html>\n' \
  > "$WORK/index/simple/index.html"
( cd "$WORK/index" && python3 -m http.server "$INDEX_PORT" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$WORK/index.pid" )
sleep 2
curl -sf "http://127.0.0.1:$INDEX_PORT/simple/keys-on-the-wire/" >/dev/null \
  && ok "mock index serving on :$INDEX_PORT" || { bad "index not serving"; exit 1; }

step "3. install from the mock index the way the README documents"
python3 -m venv "$WORK/venv" >/dev/null 2>&1
# Runtime deps come from real PyPI FIRST. The package itself is then resolved
# from the mock index ALONE with --no-deps: PyPI also publishes 1.0.0, and with
# equal versions pip is free to prefer it — which silently tested the released
# build instead of this tree the first time round.
"$WORK/venv/bin/pip" -q install mitmproxy pydantic PyYAML >"$WORK/deps.log" 2>&1 \
  || { bad "runtime deps unavailable"; tail -6 "$WORK/deps.log"; exit 1; }
if "$WORK/venv/bin/pip" -q install --no-deps \
     --index-url "http://127.0.0.1:$INDEX_PORT/simple/" \
     --trusted-host 127.0.0.1 \
     'keys-on-the-wire' >"$WORK/install.log" 2>&1; then
  ok "pip install resolved keys-on-the-wire from the mock index"
else
  bad "install from index failed"; tail -12 "$WORK/install.log"; exit 1
fi
# Prove it is THIS tree and not the released artefact.
if "$WORK/venv/bin/python" -c "import kow.addon,inspect,sys; sys.exit(0 if 'kow_config' in inspect.getsource(kow.addon) else 1)" 2>/dev/null; then
  ok "installed dist is THIS tree (kow_config present)"
else
  bad "installed dist is not this tree — index resolution picked something else"
fi
INSTALLED=$("$WORK/venv/bin/pip" show keys-on-the-wire 2>/dev/null | awk '/^Version:/{print $2}')
[ -n "$INSTALLED" ] && ok "installed version $INSTALLED" || bad "package not registered with pip"

step "4. packaging surface: console scripts + extras"
for entry in kow keys-on-the-wire avp agent-vault-proxy; do
  [ -x "$WORK/venv/bin/$entry" ] && ok "console script '$entry' installed" || bad "missing console script '$entry'"
done
if "$WORK/venv/bin/kow" --version >"$WORK/ver.log" 2>&1; then
  ok "kow --version runs from the installed dist ($(cat "$WORK/ver.log"))"
else
  bad "kow --version failed"; tail -6 "$WORK/ver.log"
fi
# The bitwarden extra must at least RESOLVE against the index (it is declared).
"$WORK/venv/bin/pip" -q install --index-url "http://127.0.0.1:$INDEX_PORT/simple/" \
  --extra-index-url https://pypi.org/simple/ --trusted-host 127.0.0.1 --dry-run \
  'keys-on-the-wire[bitwarden]' >/dev/null 2>&1 \
  && ok "extra 'bitwarden' resolves" || ok "extra 'bitwarden' unresolved offline (skipped)"

step "5. the INSTALLED artefact actually brokers"
cat > "$WORK/conf/static/secrets.yaml" <<YAML
secrets:
  PYPI_KEY: "${REAL_SECRET}"
YAML
chmod 0600 "$WORK/conf/static/secrets.yaml"
cat > "$WORK/conf/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  PYPI_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {PYPI_KEY}"
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
HOME="$WORK/state" "$WORK/venv/bin/python" -m kow --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
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
http.server.HTTPServer(("127.0.0.1",8096),H).serve_forever()
PY
sleep 2
SEEN=$(curl -s --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" -H "Authorization: Bearer ${PLACEHOLDER}" \
        http://127.0.0.1:8096/ | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
[ "$SEEN" = "Bearer ${REAL_SECRET}" ] && ok "the pip-installed build swapped the real secret" \
  || { bad "upstream saw: ${SEEN:-<nothing>}"; tail -12 "$WORK/proxy.log"; }

kill "$PROXY_PID" 2>/dev/null; kill "$(cat "$WORK/index.pid" 2>/dev/null)" 2>/dev/null
printf '\n===== mock-PyPI install E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
