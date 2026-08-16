#!/usr/bin/env bash
#
# One-command smoke test runner for kow.
# Runs all three layers (unit / BWS / full pipeline) end-to-end against
# real BWS and real Anthropic. Starts the proxy in the background, runs
# the tests, then tears the proxy down. Zero impact on your environment
# outside /tmp/avp-smoke/ and ~/.mitmproxy/ (the latter already exists).
#
# Required env (script will not source whole .env files per HARD RULE):
#   BWS_ACCESS_TOKEN  — your machine-account token for the BWS project
#                       containing ANTHROPIC_API_KEY. If unset, the script
#                       falls back to ~/.config/bws/token.
#   BWS_ORG_ID        — your Bitwarden organization UUID. Required.
#                       Find via: bws project list --output json
#
# Exit codes:
#   0 = all layers passed
#   1 = setup error (missing env, missing files)
#   2 = a layer failed
#
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
SMOKE_DIR=/tmp/avp-smoke
PROXY_LOG=$SMOKE_DIR/proxy.log
PROXY_PID_FILE=$SMOKE_DIR/proxy.pid
PROXY_PORT=14322

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
hdr()    { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

cleanup() {
    if [[ -f $PROXY_PID_FILE ]]; then
        local pid
        pid=$(cat "$PROXY_PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            hdr "Stopping proxy (pid=$pid)"
            kill "$pid" 2>/dev/null || true
            sleep 1
            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi
        rm -f "$PROXY_PID_FILE"
    fi
}
trap cleanup EXIT INT TERM

# ─── 0. Resolve secrets (one key at a time, never dump whole env files) ───
hdr "Resolving credentials"

if [[ -z "${BWS_ACCESS_TOKEN:-}" && -r ~/.config/bws/token ]]; then
    BWS_ACCESS_TOKEN=$(cat ~/.config/bws/token)
    echo "  BWS_ACCESS_TOKEN from ~/.config/bws/token"
fi
if [[ -z "${BWS_ACCESS_TOKEN:-}" ]]; then
    red "FAIL: BWS_ACCESS_TOKEN not set and could not be located."
    red "  Set it explicitly: export BWS_ACCESS_TOKEN=..."
    exit 1
fi

if [[ -z "${BWS_ORG_ID:-}" ]]; then
    red "FAIL: BWS_ORG_ID env var required."
    red "  Find your org UUID: bws project list --output json"
    red "  Then: export BWS_ORG_ID=<uuid>"
    exit 1
fi

# ─── 1. Pre-flight: venv, port availability ───
hdr "Pre-flight checks"

if [[ ! -x $REPO/.venv/bin/python ]]; then
    red "FAIL: $REPO/.venv/bin/python not found. Run 'python -m venv .venv && .venv/bin/pip install -e \".[dev]\"' first."
    exit 1
fi
echo "  venv ok"

if ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${PROXY_PORT}$"; then
    red "FAIL: port $PROXY_PORT already in use. Stop whatever is using it first."
    ss -tlnp 2>/dev/null | grep ":${PROXY_PORT}" || true
    exit 1
fi
echo "  port $PROXY_PORT free"

# ─── 2. Setup smoke directory ───
hdr "Setup /tmp/avp-smoke"

mkdir -p $SMOKE_DIR
chmod 700 $SMOKE_DIR
printf '%s' "$BWS_ACCESS_TOKEN" > $SMOKE_DIR/bws-token
chmod 400 $SMOKE_DIR/bws-token
echo "  bws-token written (mode 400, $(stat -c %s $SMOKE_DIR/bws-token) bytes)"

# Generate smoke config with real org_id substituted
SMOKE_CONFIG=$SMOKE_DIR/bindings.yaml
sed "s|REPLACE_BEFORE_RUN|$BWS_ORG_ID|" $REPO/tests/smoke/bindings.smoke.yaml > $SMOKE_CONFIG
echo "  smoke config rendered to $SMOKE_CONFIG"

# Reset audit log
: > $SMOKE_DIR/audit.jsonl
chmod 600 $SMOKE_DIR/audit.jsonl

# ─── 3. Layer 1: unit tests ───
hdr "Layer 1: unit tests"

cd "$REPO"
if ! .venv/bin/pytest -q 2>&1 | tail -5; then
    red "FAIL: unit tests did not pass. Stopping."
    exit 2
fi
green "  Layer 1 PASS"

# ─── 4. Layer 2: BWS read (no proxy) ───
hdr "Layer 2: BWS read test"

if ! BWS_ACCESS_TOKEN="$BWS_ACCESS_TOKEN" .venv/bin/python tests/smoke/layer2_bws_read.py; then
    red "FAIL: BWS read failed. Don't proceed to Layer 3 until BWS works."
    exit 2
fi
green "  Layer 2 PASS"

# ─── 5. Start proxy in background ───
hdr "Starting proxy in background"

BWS_ACCESS_TOKEN="$BWS_ACCESS_TOKEN" \
nohup .venv/bin/python -m kow \
    --set kow_config="$SMOKE_CONFIG" \
    > "$PROXY_LOG" 2>&1 &
echo $! > "$PROXY_PID_FILE"
echo "  proxy pid=$(cat $PROXY_PID_FILE), log=$PROXY_LOG"

# Wait up to 20s for the proxy to listen on the port
for i in $(seq 1 20); do
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${PROXY_PORT}$"; then
        echo "  proxy listening on 127.0.0.1:${PROXY_PORT} after ${i}s"
        break
    fi
    sleep 1
done

if ! ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${PROXY_PORT}$"; then
    red "FAIL: proxy did not start within 20s"
    echo "--- proxy log (last 40 lines) ---"
    tail -40 "$PROXY_LOG" || true
    exit 2
fi

# Confirm bound only to loopback (security sanity)
BIND=$(ss -tln 2>/dev/null | awk '{print $4}' | grep ":${PROXY_PORT}$" | head -1)
if [[ "$BIND" != "127.0.0.1:${PROXY_PORT}" ]]; then
    red "FAIL: proxy bound to $BIND, not 127.0.0.1:${PROXY_PORT}"
    exit 2
fi
echo "  bind verified: $BIND"

# Confirm CA exists
if [[ ! -f ~/.mitmproxy/mitmproxy-ca-cert.pem ]]; then
    red "FAIL: mitmproxy CA not found at ~/.mitmproxy/mitmproxy-ca-cert.pem"
    exit 2
fi
echo "  CA cert present"

# ─── 6. Layer 3: full pipeline against Anthropic ───
hdr "Layer 3: full pipeline against Anthropic"

if ! .venv/bin/python tests/smoke/layer3_proxy_anthropic.py; then
    red "FAIL: Layer 3 main test did not pass"
    echo "--- proxy log (last 30 lines) ---"
    tail -30 "$PROXY_LOG"
    echo "--- audit log (last 10 lines) ---"
    tail -10 $SMOKE_DIR/audit.jsonl || true
    exit 2
fi
green "  Layer 3 main PASS"

# ─── 7. Layer 3 negative: unbound destination ───
hdr "Layer 3 negative: unbound destination"

if ! .venv/bin/python tests/smoke/layer3_negative.py; then
    red "FAIL: negative test did not behave as expected"
    exit 2
fi
green "  Layer 3 negative PASS"

# ─── 8. Summary ───
hdr "Summary"
green "ALL SMOKE TESTS PASSED"

echo
echo "Artifacts:"
echo "  Audit log:  $SMOKE_DIR/audit.jsonl"
echo "  Proxy log:  $PROXY_LOG"
echo "  Smoke cfg:  $SMOKE_CONFIG"
echo
echo "Audit log tail:"
tail -8 $SMOKE_DIR/audit.jsonl | sed 's/^/  /'

echo
yellow "The proxy is being stopped now (cleanup trap). To run again: $0"
yellow "To fully teardown including secrets/CA: rm -rf $SMOKE_DIR"
