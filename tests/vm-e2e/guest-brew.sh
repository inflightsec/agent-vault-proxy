#!/usr/bin/env bash
# Exercises the REAL Homebrew formula from the tap, repointed at an sdist built
# from THIS tree and served locally — so the formula's own install logic (venv,
# --require-hashes lockfile install, symlinks) is what is under test, not a
# hand-rolled approximation.
#
# Runs on any Mac (Intel or Apple Silicon): a VM, a CI runner, or a laptop. It
# installs and then uninstalls the formula, leaving a scratch dir in $HOME.
# Point it at a source tree and a formula with KOW_SRC and KOW_FORMULA.
#
# The interpreter-discovery block below is duplicated from macos-e2e.sh. That is
# deliberate: these two scripts are independently runnable and a contributor may
# copy either one on its own. Twelve lines is cheaper than a shared file that
# both must carry.
set -uo pipefail

PASS=0; FAIL=0
ok(){ printf '  PASS %s\n' "$*"; PASS=$((PASS+1)); }
bad(){ printf '  FAIL %s\n' "$*"; FAIL=$((FAIL+1)); }
step(){ printf '\n== %s\n' "$*"; }

SRC="${KOW_SRC:-$HOME/kow-src}"
FORMULA="${KOW_FORMULA:-$HOME/kow-formula.rb}"
WORK=$HOME/kow-brew; rm -rf "$WORK" 2>/dev/null
mkdir -p "$WORK/dist" "$WORK/conf/static" "$WORK/state"
chmod 700 "$WORK/conf/static" "$WORK/state"
# Homebrew lives at /opt/homebrew on Apple Silicon and /usr/local on Intel, so
# the interpreter path cannot be hardcoded. macOS itself ships 3.9; kow needs 3.12+.
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /usr/local)"
# TWO passes, same rule as macos-e2e.sh: prefer a version this project ships
# wheels for, and only then anything >=3.12. A single ordered scan still picks
# Homebrew 3.14 wherever it is linked as python3, which is the failure this
# exists to avoid (no arm64 pydantic-core wheel -> source build -> dead).
SUPPORTED_PY="3.12 3.13"
CANDIDATES="python3 python3.13 python3.12
  $BREW_PREFIX/opt/python@3.13/bin/python3.13 $BREW_PREFIX/opt/python@3.12/bin/python3.12
  python3.14 $BREW_PREFIX/opt/python@3.14/bin/python3.14"
PY=""
# An explicit override wins outright (unsupported versions included — that is a
# legitimate way to reproduce a version-specific failure) and is never word-split.
if [ -n "${KOW_PY:-}" ]; then
  if command -v -- "$KOW_PY" >/dev/null 2>&1 \
     && "$KOW_PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
    PY="$(command -v -- "$KOW_PY")"
  else
    echo "KOW_PY=$KOW_PY is not a usable python >=3.12" >&2; exit 2
  fi
fi
[ -n "$PY" ] || for c in $CANDIDATES; do
  command -v -- "$c" >/dev/null 2>&1 || continue
  mm="$("$c" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)"
  case " $SUPPORTED_PY " in *" $mm "*) PY="$(command -v -- "$c")"; break ;; esac
done
if [ -z "$PY" ]; then
  for c in $CANDIDATES; do
    command -v -- "$c" >/dev/null 2>&1 || continue
    "$c" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null \
      && { PY="$(command -v -- "$c")"; break; }
  done
  [ -n "$PY" ] && printf 'warning: python %s is outside the supported range (%s); deps may lack wheels.\n' \
    "$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)" "$SUPPORTED_PY"
fi
[ -n "$PY" ] || { echo "no python >=3.12 found (brew install python@3.13)" >&2; exit 2; }
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_ANALYTICS=1
PORT=8086
PROXY_PORT=14377
REAL_SECRET="sk-live-BREW-$(head -c8 /dev/urandom | xxd -p)"
PLACEHOLDER="sk-PLACEHOLDER-brew00001111222233334"

step "1. build an sdist from this tree"
"$PY" -m venv "$WORK/buildenv" >/dev/null 2>&1
"$WORK/buildenv/bin/pip" -q install build >/dev/null 2>&1
if "$WORK/buildenv/bin/python" -m build --sdist -o "$WORK/dist" "$SRC" >"$WORK/build.log" 2>&1; then
  SDIST=$(ls "$WORK/dist"/*.tar.gz | head -1); ok "sdist built: $(basename "$SDIST")"
else
  bad "sdist build failed"; tail -10 "$WORK/build.log"; exit 1
fi
SHA=$(shasum -a 256 "$SDIST" | awk '{print $1}')

step "2. serve it, and repoint the REAL tap formula at it"
( cd "$WORK/dist" && "$PY" -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 & echo $! > "$WORK/http.pid" )
sleep 2
curl -sf "http://127.0.0.1:$PORT/$(basename "$SDIST")" -o /dev/null && ok "sdist served locally" || { bad "not served"; exit 1; }
[ -f "$FORMULA" ] || { bad "tap formula not found at $FORMULA (set KOW_FORMULA)"; exit 1; }
# brew refuses a loose .rb path — the formula must live in a tap.
brew tap-new kowtest/local --no-git >/dev/null 2>&1
TAPDIR=$(brew --repository kowtest/local)/Formula
mkdir -p "$TAPDIR"
"$PY" - "$FORMULA" "$TAPDIR/keys-on-the-wire.rb" \
       "http://127.0.0.1:$PORT/$(basename "$SDIST")" "$SHA" <<'PY'
import re, sys
src, dst, url, sha = sys.argv[1:5]
t = open(src).read()
t = re.sub(r'url "https://files\.pythonhosted\.org/[^"]+"', f'url "{url}"', t)
t = re.sub(r'sha256 "[0-9a-f]{64}"', f'sha256 "{sha}"', t)
open(dst, "w").write(t)
PY
grep -q "127.0.0.1:$PORT" "$TAPDIR/keys-on-the-wire.rb" && ok "formula repointed at the local sdist" || bad "formula rewrite failed"

step "3. brew install --build-from-source (the formula's own logic)"
brew uninstall --force keys-on-the-wire kowtest/local/keys-on-the-wire >/dev/null 2>&1
if brew install --build-from-source kowtest/local/keys-on-the-wire >"$WORK/brew.log" 2>&1; then
  ok "brew install succeeded"
else
  bad "brew install failed"; tail -25 "$WORK/brew.log"; exit 1
fi
PREFIX=$(brew --prefix keys-on-the-wire 2>/dev/null)
[ -n "$PREFIX" ] && ok "brew reports prefix $PREFIX" || bad "no brew prefix"

step "4. what the formula promises it installs"
for b in kow avp; do
  [ -x "$(brew --prefix)/bin/$b" ] && ok "symlink '$b' installed in brew bin" || bad "missing symlink '$b'"
done
"$(brew --prefix)/bin/kow" --version >/dev/null 2>&1 && ok "brew-installed kow --version runs" || bad "kow --version failed"
"$(brew --prefix)/bin/kow" doctor --help >/dev/null 2>&1 && ok "kow doctor reachable" || bad "kow doctor missing"

step "5. the brew-installed build actually brokers"
cat > "$WORK/conf/static/secrets.yaml" <<YAML
secrets:
  BREW_KEY: "${REAL_SECRET}"
YAML
chmod 600 "$WORK/conf/static/secrets.yaml"
cat > "$WORK/conf/bindings.yaml" <<YAML
version: 1
binding_source: file
secrets:
  BREW_KEY:
    placeholder: "${PLACEHOLDER}"
    inject:
      header: "Authorization"
      format: "Bearer {BREW_KEY}"
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
HOME="$WORK/state" "$PREFIX/libexec/bin/python" -m kow --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
  --set kow_config="$WORK/conf/bindings.yaml" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
for _ in $(seq 1 30); do
  curl -s -o /dev/null --max-time 2 -x "http://127.0.0.1:$PROXY_PORT" http://healthz.kow.invalid/healthz && break
  sleep 1
done
"$PY" - <<'PY' >/dev/null 2>&1 &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        b=json.dumps({"auth":self.headers.get("Authorization","")}).encode()
        self.send_response(200); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",8094),H).serve_forever()
PY
sleep 2
SEEN=$(curl -s --max-time 10 -x "http://127.0.0.1:$PROXY_PORT" -H "Authorization: Bearer ${PLACEHOLDER}" \
        http://127.0.0.1:8094/ | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["auth"])' 2>/dev/null)
if [ "$SEEN" = "Bearer ${REAL_SECRET}" ]; then ok "brew-installed kow swapped the real secret"
elif [ "$SEEN" = "Bearer ${PLACEHOLDER}" ]; then bad "no substitution: upstream saw the placeholder unchanged"
elif [ -z "$SEEN" ]; then bad "upstream saw nothing (request did not complete)"
# Never echo the observed value: on a partial-substitution failure it IS the
# secret, and CI logs are public.
else bad "upstream saw an unexpected value (${#SEEN} bytes, withheld)"; fi
if grep -q "$REAL_SECRET" "$WORK/proxy.log" 2>/dev/null; then bad "SECRET IN PROXY LOG"; else ok "no secret bytes in proxy log"; fi

step "6. formula caveats must match reality"
CAV=$(brew info keys-on-the-wire 2>/dev/null)
echo "$CAV" | grep -q '_avp user' && bad "caveats still say '_avp user' (now _kow)" || ok "caveats do not name the old service user"
echo "$CAV" | grep -q 'etc/agent-vault-proxy' && bad "caveats still point at /usr/local/etc/agent-vault-proxy" || ok "caveats use current paths"
echo "$CAV" | grep -q '.config/avp/env' && bad "caveats still say ~/.config/avp/env" || ok "caveats use current env path"

kill "$PROXY_PID" 2>/dev/null; kill "$(cat "$WORK/http.pid" 2>/dev/null)" 2>/dev/null
brew uninstall --force keys-on-the-wire >/dev/null 2>&1
printf '\n===== Homebrew E2E: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
