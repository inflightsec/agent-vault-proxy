#!/usr/bin/env bash
# Container-free end-to-end test for agent-vault-proxy.
#
# Stands up a REAL mitmdump proxy process (static backend, file bindings) plus a
# local echo upstream, then drives live HTTP through the proxy and asserts on
# the wire: header / body / multi / composite-header / composite-body
# substitution, fail-closed 503, deny-unbound 403, correct audit, and NO secret
# bytes in any log. Same assertions as tests/docker-e2e, without a container
# runtime — so it runs in CI (the main pytest job) and on any dev box.
#
# Security posture:
#   * everything lives in a per-run mktemp dir (mode 0700), removed on exit;
#   * the static secrets file is generated with RANDOM values, chmod 0600, and
#     is never committed (only placeholders live in bindings.template.yaml);
#   * proxy + echo bind 127.0.0.1 only; mitmproxy's confdir is inside the temp
#     dir (no ~/.mitmproxy pollution); no external network is contacted;
#   * the proxy runs in its own process group and is always reaped.
set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
HERE="$REPO/tests/local-e2e"
PY="${PYTHON:-python}"
MITM="${MITMDUMP:-mitmdump}"

# The pytest wrapper owns the temp dir (E2E_WORKDIR) so it is ALWAYS removed —
# even if this script is SIGKILLed on a pytest timeout. Standalone runs mktemp
# their own and clean it up in the EXIT trap.
if [ -n "${E2E_WORKDIR:-}" ]; then
    WORKDIR="$E2E_WORKDIR"
    OWN_WORKDIR=0
else
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/avp-local-e2e.XXXXXX") \
        || { echo "FAIL: mktemp -d failed"; exit 2; }
    OWN_WORKDIR=1
fi
[ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] || { echo "FAIL: workdir invalid"; exit 2; }
chmod 700 "$WORKDIR" 2>/dev/null || true

pick_port() {
    for p in $(seq "$1" "$2"); do
        if ! ss -tln 2>/dev/null | grep -qE ":${p}([[:space:]]|\$)"; then echo "$p"; return 0; fi
    done
    return 1
}

cleanup() {
    [ -n "${ECHO_PID:-}" ] && kill "$ECHO_PID" 2>/dev/null
    [ -n "${PROXY_PID:-}" ] && kill "$PROXY_PID" 2>/dev/null
    sleep 1
    [ -n "${PROXY_PID:-}" ] && kill -9 "$PROXY_PID" 2>/dev/null
    # Only remove the workdir if THIS script created it; when pytest owns it
    # (E2E_WORKDIR) the wrapper's finally removes it even on a SIGKILL timeout.
    [ "${OWN_WORKDIR:-0}" = 1 ] && [ -d "${WORKDIR:-}" ] && rm -rf "$WORKDIR"
    true
}
trap cleanup EXIT
# Convert TERM/INT into a normal exit so the EXIT trap (cleanup) still runs.
trap 'exit 143' TERM
trap 'exit 130' INT

# ── generate the static secrets file (random values, never committed) ────────
# Generate + validate every value BEFORE writing, so a broken interpreter can
# never yield degenerate secrets or a half-written file we then test against.
rand() { "$PY" -c "import secrets; print(secrets.token_hex(16))"; }
K_API=$(rand) && K_BODY=$(rand) && K_MULTI=$(rand) && E_USER=$(rand) && E_PASS=$(rand) \
    || { echo "FAIL: secret generation via $PY"; exit 2; }
for v in "$K_API" "$K_BODY" "$K_MULTI" "$E_USER" "$E_PASS"; do
    [ -n "$v" ] || { echo "FAIL: a generated secret was empty"; exit 2; }
done
SECRETS="$WORKDIR/secrets.yaml"
AUDIT="$WORKDIR/audit.jsonl"
{
    echo "secrets:"
    echo "  TEST_API_KEY: \"e2e-key-$K_API\""
    echo "  TEST_BODY_KEY: \"e2e-body-$K_BODY\""
    echo "  TEST_MULTI_KEY: \"e2e-multi-$K_MULTI\""
    echo "  E2E_USER: \"e2e-user-$E_USER\""
    echo "  E2E_PASS: \"e2e-pass-$E_PASS\""
    # FAILCLOSED_KEY intentionally ABSENT -> exercises the fail-closed path.
} > "$SECRETS" || { echo "FAIL: writing secrets file"; exit 2; }
chmod 600 "$SECRETS" || { echo "FAIL: chmod secrets file"; exit 2; }

# Delimiter-safe substitution (a sed s#...# would break on a special char in a
# hostile TMPDIR path); a plain Python str.replace cannot.
"$PY" -c "import sys; t=open(sys.argv[1]).read(); open(sys.argv[2],'w').write(t.replace('__SECRETS_YAML__',sys.argv[3]).replace('__AUDIT_JSONL__',sys.argv[4]))" \
    "$HERE/bindings.template.yaml" "$WORKDIR/bindings.yaml" "$SECRETS" "$AUDIT" \
    || { echo "FAIL: rendering bindings"; exit 2; }
[ -s "$WORKDIR/bindings.yaml" ] || { echo "FAIL: rendered bindings empty"; exit 2; }

PROXY_PORT=$(pick_port 14601 14680) || { echo "no free proxy port"; exit 2; }
ECHO_PORT=$(pick_port 14681 14760) || { echo "no free echo port"; exit 2; }

# ── echo upstream ────────────────────────────────────────────────────────────
"$PY" "$HERE/echo_server.py" "$ECHO_PORT" &
ECHO_PID=$!
echo_up=0
for _ in $(seq 1 40); do
    if ss -tln 2>/dev/null | grep -qE ":${ECHO_PORT}([[:space:]]|\$)"; then echo_up=1; break; fi
    sleep 0.25
done
[ "$echo_up" = 1 ] || { echo "FAIL: echo upstream never listened on :${ECHO_PORT}"; exit 2; }

# ── real proxy process ───────────────────────────────────────────────────────
# NOT setsid: kept in this script's process group so a pytest-timeout SIGKILL of
# the group reaps it too (no orphan); the EXIT trap reaps it on normal runs.
"$MITM" -s "$REPO/src/kow/addon.py" \
    --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" \
    --set confdir="$WORKDIR/mitm" \
    --set avp_config="$WORKDIR/bindings.yaml" > "$WORKDIR/proxy.log" 2>&1 &
PROXY_PID=$!

listening=0
for _ in $(seq 1 60); do
    if ss -tln 2>/dev/null | grep -qE ":${PROXY_PORT}([[:space:]]|\$)"; then listening=1; break; fi
    sleep 0.5
done
if [ "$listening" != 1 ]; then
    echo "FAIL: proxy never listened on :${PROXY_PORT}"
    echo "----- proxy.log -----"; tail -40 "$WORKDIR/proxy.log"
    exit 2
fi

# ── assertions ───────────────────────────────────────────────────────────────
"$PY" "$HERE/client.py" "$ECHO_PORT" "$PROXY_PORT" "$WORKDIR"
RC=$?
if [ "$RC" != 0 ]; then echo "----- proxy.log tail -----"; tail -25 "$WORKDIR/proxy.log"; fi
exit $RC
